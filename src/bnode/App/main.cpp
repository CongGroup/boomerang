#include "../../common/utils.hpp"
#include "../../common/sgx.hpp"
#include "../../common/json.hpp"
#include "../../common/utils.hpp"
#include "../../common/ds.hpp"

#include "../../../thirdparty/lambertW/LambertW.h"

#include <cassert>
#include <vector>
#include <list>
#include <memory>
#include <iostream>
#include <string>
#include <thread>
#include <fstream>
#include <mutex>
#include <deque>

#include <grpcpp/grpcpp.h>
#include <grpc/support/log.h>

#include "boomerang.grpc.pb.h"

using grpc::Server;
using grpc::ServerAsyncResponseWriter;
using grpc::ClientAsyncResponseReader;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::ClientContext;
using grpc::ServerCompletionQueue;
using grpc::CompletionQueue;
using grpc::Status;
using boomerang::Payload;
using boomerang::PayloadWithRes;
using boomerang::BoomerangService;

LogHelper logging;

struct AsyncClientCall {
    Payload reply;

    ClientContext context;

    Status status;

    std::unique_ptr<ClientAsyncResponseReader<Payload>> response_reader;
};

enum CallStatus { CREATE, PROCESS, FINISH };
class CallData {
private:
    BoomerangService::AsyncService* service_;
    ServerCompletionQueue* cq_;
    ServerContext ctx_;

    PayloadWithRes request_;
    Payload reply_;

    ServerAsyncResponseWriter<Payload> responder_;

    CallStatus status_;  // The current serving state.

public:
    CallData(BoomerangService::AsyncService* service, ServerCompletionQueue* cq): service_(service), cq_(cq), responder_(&ctx_), status_(CallStatus::CREATE) {
        process();
    }

    void process() {
        if (status_ == CallStatus::CREATE) {
            status_ = CallStatus::PROCESS;

            service_->RequestSendMsg(&ctx_, &request_, &responder_, cq_, cq_, this);
        }
        else if (status_ == CallStatus::PROCESS) {
            new CallData(service_, cq_);

        }
        else {
            GPR_ASSERT(status_ == CallStatus::FINISH);
            delete this;
        }
    }

    void response() {
        status_ = CallStatus::FINISH;
        responder_.Finish(reply_, Status::OK, this);  // it will add CallDta to cq with Status==Finish!
    }

    uint64_t get_req_reserved() {
        return request_.reserved();
    }

    uint8_t* get_req_data() {
        return reinterpret_cast<uint8_t*>(const_cast<char*>(request_.data().data()));
    }

    size_t get_req_data_size() {
        return request_.data().size();
    }

    CallStatus get_status() {
        return status_;
    }

    void set_reply_data(const std::string& s) {
        reply_.set_data(s);
    }
};


class BoomerangBNode final {
private:
    // gRPC correlation
    BoomerangService::AsyncService service_;
    std::unique_ptr<Server> server_;

    std::vector<std::unique_ptr<ServerCompletionQueue>> cqs_from_enode_;
    std::vector<std::thread> recv_pkts_from_enode_threads_;

    std::unordered_map<uint64_t, CallData*> mapping_enodeid_pkt_;

    // Boomerang correlation
    size_t recv_counter_ = 0;
    size_t round_num_ = 0;

    size_t id_;

    size_t clt_num_;
    size_t enode_num_;
    size_t bnode_num_;

    size_t pkt_size_;
    size_t B_;
    bool use_B_padding_;
    size_t total_round_num_;

    std::mutex mtx_;

    uint8_t* bnode2enode_buffer_;
    size_t bnode2enode_buffer_size_;

public:
    BoomerangBNode(size_t id, const std::string& config_path, size_t user_num, size_t round_num, size_t parallel_num, const std::string& interface_name, bool use_B_padding, size_t enode_num, size_t bnode_num) {
        // Set id
        id_ = id;
        // logging.info("Set id = " + std::to_string(id_));

        // Load network info
        std::ifstream in(config_path);
        if (in.fail()) {
            throw std::logic_error("File is not exist!");
        }
        nlohmann::json js;
        in >> js;

        clt_num_ = js["clt_addr"].size();
        // logging.info("Set client num = " + std::to_string(clt_num_));
        enode_num_ = enode_num;
        // logging.info("Set load balancer num = " + std::to_string(enode_num_));
        bnode_num_ = bnode_num;
        // logging.info("Set b_node num = " + std::to_string(bnode_num_));

        if (id_ == 0) {
            logging.info("Set client num = " + std::to_string(clt_num_));
            logging.info("Set load balancer num = " + std::to_string(enode_num_));
            logging.info("Set b_node num = " + std::to_string(bnode_num_));
        }

        listen(get_interface_ip(interface_name) + ":" + get_port(js["bnode_addr"][id]), parallel_num);

        total_round_num_ = round_num;

        // Set padding type
        use_B_padding_ = use_B_padding;

        // Set other attributes
        pkt_size_ = PKT_SIZE;
        // logging.info("Set packet size = " + std::to_string(pkt_size_));

        B_ = use_B_padding_ ? get_B(int(std::ceil(1.f * user_num / enode_num_)), bnode_num_) : 1;  // TODO
        // logging.info("Set B = " + std::to_string(B_));

        size_t bit_bigger_num = get_B(user_num, bnode_num_);
        bit_bigger_num = bit_bigger_num < (enode_num_* B_) ? (enode_num_ * B_) : bit_bigger_num;
        bnode2enode_buffer_ = new uint8_t[bit_bigger_num * pkt_size_];
        bnode2enode_buffer_size_ = bit_bigger_num * pkt_size_;
    }

    ~BoomerangBNode() {
        server_->Shutdown();
        for (auto& cq : cqs_from_enode_) {
            cq->Shutdown();
        }

        if (bnode2enode_buffer_ != nullptr) {
            delete bnode2enode_buffer_;
        }
    }

    void recv_pkts_from_enode_mt() {
        for (size_t k = 0;k < cqs_from_enode_.size();++k) {
            recv_pkts_from_enode_threads_.emplace_back([this, k] { this->recv_pkts_from_enode_st(k); });
        }
    }

    void join() {
        for (auto& th : recv_pkts_from_enode_threads_) {
            th.join();
        }
    }

private:
    void listen(const std::string& addr, size_t cqs_from_enode_num) {
        ServerBuilder builder;
        builder.SetMaxReceiveMessageSize(1024 * 1024 * 1024);  // 1G
        builder.SetMaxSendMessageSize(1024 * 1024 * 1024);  // 1G
        builder.AddListeningPort(addr, grpc::InsecureServerCredentials());
        builder.RegisterService(&service_);
        for (int k = cqs_from_enode_num;k--;) {
            cqs_from_enode_.emplace_back(builder.AddCompletionQueue());
        }
        server_ = builder.BuildAndStart();
        // logging.info("Listen on " + addr);
    }

    void recv_pkts_from_enode_st(size_t cq_id) {
        std::deque<int64_t> cost_time;  // Test

        new CallData(&service_, cqs_from_enode_[cq_id].get());
        void* tag;  // uniquely identifies a request.
        bool ok;
        while (true) {
            GPR_ASSERT(cqs_from_enode_[cq_id]->Next(&tag, &ok));
            GPR_ASSERT(ok);

            CallData* cd_from_enode = static_cast<CallData*>(tag);

            if (cd_from_enode->get_status() == CallStatus::FINISH) {
                cd_from_enode->process();  // status==FINISH: delete CallData
                continue;
            }
            cd_from_enode->process();  // status==PROCESS: create empty CallData, prepare for next input

            mtx_.lock();
            mapping_enodeid_pkt_[cd_from_enode->get_req_reserved()] = cd_from_enode;
            if (mapping_enodeid_pkt_.size() >= enode_num_) {
                assert(mapping_enodeid_pkt_.size() == enode_num_);
                ++round_num_;
                // logging.info("Start " + std::to_string(round_num_) + " round [3.b_node handle and send back to load balancer]");

                bool TEST_NETWORK_LATENCY = false;  // TODO

                if (!TEST_NETWORK_LATENCY) {
                    auto prev_tp = std::chrono::system_clock::now();

                    // Handle in enclave
                    std::vector<uint8_t*> pkts_p;
                    std::vector<size_t> lens(enode_num_, 0);
                    for (auto& pair : mapping_enodeid_pkt_) {
                        uint8_t* block_p = pair.second->get_req_data();
                        size_t len = pair.second->get_req_data_size() / pkt_size_;
                        lens[pair.second->get_req_reserved()] = len;
                        for (size_t l = 0;l < len;++l) {
                            pkts_p.push_back(block_p);
                            block_p += pkt_size_;
                        }
                    }
                    size_t lens_sum = std::accumulate(lens.begin(), lens.end(), static_cast<size_t>(0));
                    size_t lens_data[enode_num_]{};
                    if (ecall_handle_blocks(global_eid, pkts_p.data(), lens_sum, pkt_size_, bnode2enode_buffer_, lens_sum * pkt_size_, lens_data, enode_num_) != SGX_SUCCESS)
                    {
                        logging.error("Error: ecall_handle_blocks\n");
                    }
                    memcpy(lens.data(), lens_data, enode_num_ * sizeof(size_t));

                    if (id_ == 0) {
                        auto current_tp = std::chrono::system_clock::now();
                        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(current_tp - prev_tp);
                        cost_time.push_back(duration.count());
                        uint64_t cost_sum = std::accumulate(cost_time.begin(), cost_time.end(), 0);
                        if (round_num_ == 1) {
                            logging.info("Process batch cost(warmup) " + std::to_string(cost_sum / std::chrono::milliseconds::period::num / cost_time.size()) + " ms");
                        }
                        if (round_num_ == total_round_num_) {
                            logging.info("Process batch cost(mean) " + std::to_string(cost_sum / std::chrono::milliseconds::period::num / cost_time.size()) + " ms");
                        }
                        if (round_num_ == 3) {  // skip three rounds
                            cost_time.clear();
                        }
                    }

                    // Send blocks to all load balancer
                    assert(lens.size() == enode_num_);
                    uint8_t* bnode2enode_buffer_p = bnode2enode_buffer_;
                    for (size_t enode_id = 0;enode_id < enode_num_;++enode_id) {
                        mapping_enodeid_pkt_[enode_id]->set_reply_data(std::string(bnode2enode_buffer_p, bnode2enode_buffer_p + lens[enode_id] * pkt_size_));
                        mapping_enodeid_pkt_[enode_id]->response();
                        bnode2enode_buffer_p += lens[enode_id] * pkt_size_;
                    }
                }
                else {  // Test network latency
                    for (size_t enode_id = 0;enode_id < enode_num_;++enode_id) {
                        mapping_enodeid_pkt_[enode_id]->set_reply_data(std::string(mapping_enodeid_pkt_[enode_id]->get_req_data(), mapping_enodeid_pkt_[enode_id]->get_req_data() + mapping_enodeid_pkt_[enode_id]->get_req_data_size()));
                        mapping_enodeid_pkt_[enode_id]->response();
                    }
                }

                mapping_enodeid_pkt_.clear();
            }
            mtx_.unlock();
        }
    }

    int get_B(size_t m, size_t n, size_t lamda = 128) {
        if (n == 1) {
            return m / n;
        }
        else {
            double alpha = lamda / std::log2(n);
            double x1 = m / n;
            double x2 = m * std::log(n) / n / 3;
            double x3 = 1 - (std::log(std::log(n)) / (2 * alpha * std::log(n)));
            double b = x1 + 4 * std::sqrt(x2 * x3);
            return int(std::ceil(b));
        }
    }

};

#include "docopt.h"
static const char USAGE[] =
R"(
    Usage:
      exec [--id <id>] [-u <user_num>] [-r <round_num>] [-p <parallel_num>] [-e <enclave_path>] [-c <config_path>] [-i <interface_name>] [-w <worker_thread_num>] [--bnode-num <bnode_num>] [--enode-num <enode_num>] [--use-B]

    Options:
      -h --help                                     Show this screen.
      --version                                     Show version.
      --id <id>                                     Id of server [default: 0]
      -u --user-num <user_num>                      Num of simulated users [default: 100]
      -r --round-num <round_num>                    Num of synchronized rounds [default: 10]
      -p --parallel-num <parallel_num>              Parallel num of grpc recv [default: 1]
      -e --enclave-path <enclave_path>              Path of the signed enclave file [default: ../build/BNodeEnclaveLib.signed.so]
      -c --config-path <config_path>                Path of the network config file [default: ../config/config_local.json]
      -i --interface-name <interface_name>          Specified network interface [default: lo]
      -w --worker-thread-num <worker_thread_num>    Num of worker threads in enclave [default: 1]
      --bnode-num <bnode_num>                       Num of all bnodes [default: 1]
      --enode-num <enode_num>                       Num of all enodes [default: 1]
      --use-B                                       Setting batch size B according to Theorem 4.1
)";

#include "Enclave_u.h"

void ocall_print_string(const char* str)
{
    std::string out_str(str);
    logging.info(out_str);
}

decltype(std::chrono::system_clock::now()) tp1, tp2;

void ocall_set_time_point()
{
    tp1 = std::chrono::system_clock::now();
}

void ocall_probe_time()
{
    tp2 = std::chrono::system_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(tp2 - tp1);
    std::cout << "Cost = "
        << double(duration.count()) * std::chrono::microseconds::period::num / std::chrono::microseconds::period::den
        << std::endl;
    tp1 = std::chrono::system_clock::now();
}

void ocall_print_time()
{
    tp2 = std::chrono::system_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(tp2 - tp1);
    std::cout << "Cost = "
        << double(duration.count()) * std::chrono::microseconds::period::num / std::chrono::microseconds::period::den
        << std::endl;
}

void u_sgxssl_ftime(void* timeptr, uint32_t timeb_len) {

}

int main(int argc, char** argv)
{
    std::map<std::string, docopt::value> docopt_args = docopt::docopt(
        USAGE,
        { argv + 1, argv + argc },
        true,  // show help if requested
        "Boomerang BNode");  // version string

    logging.set_id_prefix(docopt_args["--id"].asLong(), "BNode");

    if (docopt_args["--id"].asLong() == 0) {
        logging.info("Input args:");
        std::string args_str = "";
        for (auto arg : docopt_args) {
            args_str += arg.first + " " + (arg.second.isBool() ? (arg.second.asBool() ? "true" : "false") : arg.second.asString()) + "; ";
        }
        logging.info(args_str);
    }

    create_enclave(docopt_args["--enclave-path"].asString());

    BoomerangBNode boomerang_bnode(docopt_args["--id"].asLong(), docopt_args["--config-path"].asString(), docopt_args["--user-num"].asLong(), docopt_args["--round-num"].asLong(), docopt_args["--parallel-num"].asLong(), docopt_args["--interface-name"].asString(), docopt_args["--use-B"].asBool(), docopt_args["--enode-num"].asLong(), docopt_args["--bnode-num"].asLong());
    boomerang_bnode.recv_pkts_from_enode_mt();

    if (ecall_set_worker_thread_num(global_eid, docopt_args["--worker-thread-num"].asLong()) != SGX_SUCCESS) {
        logging.error("Error: ecall_set_worker_thread_num");
    }
    std::vector<std::thread> enclave_worker_threads;
    for (size_t thread_id = 1;thread_id < docopt_args["--worker-thread-num"].asLong();++thread_id) {
        enclave_worker_threads.emplace_back([thread_id] {
            if (ecall_start_worker_loop(global_eid, thread_id) != SGX_SUCCESS) {
                logging.error("Error: ecall_start_worker_loop");
            }
            });
    }

    for (size_t k = 0;k < enclave_worker_threads.size();++k) {
        enclave_worker_threads[k].join();
    }
    boomerang_bnode.join();

    return 0;
}