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
using boomerang::PayloadWithRes;
using boomerang::BoomerangService;
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
    CallData(BoomerangService::AsyncService* service, ServerCompletionQueue* cq) : service_(service), cq_(cq), responder_(&ctx_), status_(CallStatus::CREATE) {
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

    std::string get_req_data_str() {
        return request_.data();
    }

    CallStatus get_status() {
        return status_;
    }

    void set_reply_data(const std::string& s) {
        reply_.set_data(s);
    }
};


class BoomerangTestServer final {
private:
    // gRPC correlation
    BoomerangService::AsyncService service_;
    std::unique_ptr<Server> server_;
    std::vector<std::unique_ptr<BoomerangService::Stub>> connections_bnode_;

    std::vector<std::unique_ptr<ServerCompletionQueue>> cqs_from_clt_;
    std::vector<std::thread> recv_pkts_from_clt_threads_;

    std::unordered_map<uint64_t, CallData*> mapping_ip_cd_;

    // Boomerang correlation
    size_t recv_counter_ = 0;
    size_t round_num_ = 0;

    size_t id_;

    size_t pkt_size_;

    std::mutex mtx_;

    uint8_t* enode2clt_buffer_;

    size_t start_handle_threshold_;

public:
    BoomerangTestServer(size_t id, const std::string& network_filename, size_t parallel_num, const std::string& interface_name) :start_handle_threshold_(static_cast<size_t>(1) << (sizeof(size_t) * 8 - 1)) {
        // Set id
        id_ = id;
        logging.info("Set id = " + std::to_string(id_));

        // Load network info
        std::ifstream in(network_filename);
        if (in.fail()) {
            throw std::logic_error("File is not exist!");
        }
        nlohmann::json js;
        in >> js;

        listen(get_interface_ip(interface_name) + ":" + get_port(js["bnode_addr"][id]), parallel_num);

        // Set other attributes
        pkt_size_ = PKT_SIZE;  // TODO
        logging.info("Set packet size = " + std::to_string(pkt_size_));

        enode2clt_buffer_ = nullptr;
    }

    ~BoomerangTestServer() {
        server_->Shutdown();
        for (auto& cq : cqs_from_clt_) {
            cq->Shutdown();
        }

        if (enode2clt_buffer_ != nullptr) {
            delete enode2clt_buffer_;
        }
    }

    void recv_pkts_from_clt_mt() {
        for (size_t k = 0;k < cqs_from_clt_.size();++k) {
            recv_pkts_from_clt_threads_.emplace_back([this, k] { this->recv_pkts_from_clt_st(k); });
        }
    }


    void join() {
        for (auto& th : recv_pkts_from_clt_threads_) {
            th.join();
        }
    }

private:
    void listen(const std::string& addr, size_t cqs_from_clt_num) {
        ServerBuilder builder;
        builder.AddListeningPort(addr, grpc::InsecureServerCredentials());
        builder.RegisterService(&service_);
        for (int k = cqs_from_clt_num;k--;) {
            cqs_from_clt_.emplace_back(builder.AddCompletionQueue());
        }
        server_ = builder.BuildAndStart();
        logging.info("Listen on " + addr);
    }

    void recv_pkts_from_clt_st(size_t cq_id) {
        new CallData(&service_, cqs_from_clt_[cq_id].get());
        void* tag;  // uniquely identifies a request.
        bool ok;
        while (true) {
            GPR_ASSERT(cqs_from_clt_[cq_id]->Next(&tag, &ok));
            GPR_ASSERT(ok);

            CallData* cd_from_clt = static_cast<CallData*>(tag);

            if (cd_from_clt->get_status() == CallStatus::FINISH) {
                cd_from_clt->process();  // delte CallData
                continue;
            }
            cd_from_clt->process();  // create empty CallData, prepare for next input 

            mtx_.lock();
            if (cd_from_clt->get_req_reserved() != 0) {
                mapping_ip_cd_[cd_from_clt->get_req_reserved()] = cd_from_clt;
            }
            else {  // ip==0 donate end signal, take care that async send is not sequential! recv packets are disorded
                start_handle_threshold_ = std::stoi(cd_from_clt->get_req_data_str());
                // Response immediately
                cd_from_clt->response();
            }

            if (mapping_ip_cd_.size() >= start_handle_threshold_) {
                // logging.info("Start " + std::to_string(++round_num_) + " round [2.test server handle]");

                // Handle in enclave
                if (enode2clt_buffer_ == nullptr) {
                    enode2clt_buffer_ = new uint8_t[mapping_ip_cd_.size() * (pkt_size_ + sizeof(uint64_t))];
                }  // TODO
                uint8_t** pkts_p = new uint8_t * [mapping_ip_cd_.size()];
                size_t kk = 0;
                for (auto& pair : mapping_ip_cd_) {
                    pkts_p[kk++] = pair.second->get_req_data();
                }
                size_t valid_out_data_size;
                if (ecall_handle_batch(global_eid, pkts_p, mapping_ip_cd_.size(), pkt_size_, enode2clt_buffer_, (pkt_size_ + sizeof(uint64_t)) * mapping_ip_cd_.size(), &valid_out_data_size) != SGX_SUCCESS) {
                    logging.error("Error: ecall_handle_batch");
                }
                delete[] pkts_p;

                // logging.info("Start " + std::to_string(round_num_) + " round [3.test server send back]");

                start_handle_threshold_ = (static_cast<size_t>(0) - static_cast<size_t>(1));

                // enode2clt_buffer_ => mapping_ip_pkt
                for (auto& pair : mapping_ip_cd_) {
                    pair.second->set_reply_data("x");  // donate dedup pkt
                }
                for (size_t k = 0;k < valid_out_data_size;++k) {
                    uint64_t ip;
                    memcpy(&ip, enode2clt_buffer_ + k * (pkt_size_ + sizeof(uint64_t)), sizeof(uint64_t));

                    // std::cout << ip << std::endl;

                    if (mapping_ip_cd_.find(ip) != mapping_ip_cd_.end()) {
                        mapping_ip_cd_[ip]->set_reply_data(std::string(enode2clt_buffer_ + k * (pkt_size_ + sizeof(uint64_t)) + sizeof(uint64_t), enode2clt_buffer_ + (k + 1) * (pkt_size_ + sizeof(uint64_t))));
                    }
                    else {
                        logging.error("Invalid send back ip: " + std::to_string(ip));
                        throw std::logic_error("Invalid send back ip");
                    }
                }

                // Send back
                for (auto& pair : mapping_ip_cd_) {
                    pair.second->response();
                }
                mapping_ip_cd_.clear();
            }
            mtx_.unlock();
        }
    }
};

#include "docopt.h"
static const char USAGE[] =
R"(
    Usage:
      exec [--id <id>] [-p <parallel_num>] [-e <enclave_path>] [-c <config_path>] [-i <interface_name>] [-w <worker_thread_num>]

    Options:
      -h --help                                     Show this screen.
      --version                                     Show version.
      --id <id>                                     Id of server [default: 0]
      -p --parallel-num <parallel_num>              Parallel num of grpc recv [default: 1]
      -e --enclave-path <enclave_path>              Path of the signed enclave file [default: ../build/TestBNodeEnclaveLib.signed.so]
      -c --config-path <config_path>                Path of the network config file [default: ../config/config_local.json]
      -i --interface-name <interface_name>          Specified network interface [default: lo]
      -w --worker-thread-num <worker_thread_num>    Num of worker threads in enclave [default: 1]
)";

#include "Enclave_u.h"

void ocall_print_string(const char* str)
{
    std::cout << str;
}

void u_sgxssl_ftime(void * timeptr, uint32_t timeb_len){

}

int main(int argc, char** argv)
{
    std::map<std::string, docopt::value> docopt_args = docopt::docopt(
        USAGE,
        { argv + 1, argv + argc },
        true,  // show help if requested
        "Boomerang Test Server");  // version string

    logging.set_id_prefix(docopt_args["--id"].asLong(), "TestServer");

    logging.info("Input args:");
    std::string args_str = "";
    for (auto arg : docopt_args) {
        args_str += arg.first + " " + arg.second.asString() + "; ";
    }
    logging.info(args_str);

    create_enclave(docopt_args["--enclave-path"].asString());

    BoomerangTestServer boomerang_ts(docopt_args["--id"].asLong(), docopt_args["--config-path"].asString(), docopt_args["--parallel-num"].asLong(), docopt_args["--interface-name"].asString());

    boomerang_ts.recv_pkts_from_clt_mt();

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
    boomerang_ts.join();

    return 0;
}