#include "../../common/json.hpp"
#include "../../common/ds.hpp"
#include "../../common/utils.hpp"

#include <iostream>
#include <memory>
#include <string>
#include <fstream>

#include <grpcpp/grpcpp.h>
#include <grpc/support/log.h>
#include <thread>
#include <chrono>
#include <bitset>
#include <deque>

#include "cryptolib.h"

#include "boomerang.grpc.pb.h"

using grpc::Channel;
using grpc::ClientAsyncResponseReader;
using grpc::ClientContext;
using grpc::CompletionQueue;
using grpc::Status;
using boomerang::Payload;
using boomerang::PayloadWithRes;
using boomerang::BoomerangService;

LogHelper logging;

class BoomerangTestClient {
private:
    // gRPC correlation
    struct AsyncClientCall {
        Payload reply;

        ClientContext context;

        Status status;

        std::unique_ptr<ClientAsyncResponseReader<Payload>> response_reader;
    };

    std::vector<CompletionQueue*> cqs_;
    std::vector<std::thread> recv_pkts_from_enode_threads_;
    std::mutex recv_mtx_;

    std::vector<std::unique_ptr<BoomerangService::Stub>> connections_bnode_;

    // Boomerang correlation
    size_t recv_counter_ = 0;

    size_t id_;

    std::vector<uint64_t> users_;
    std::vector<uint128_t> dd_ids_;

    Limit limit_;

    std::chrono::_V2::system_clock::time_point tp_base_;
    std::mutex mtx_;
    std::deque<int64_t> latency_;

public:
    explicit BoomerangTestClient(size_t id, size_t user_num, size_t parallel_num, const std::string& network_filename) {
        // Set id
        id_ = id;
        logging.info("Set id = " + std::to_string(id_));

        // Multi send-recv
        for (int k = parallel_num;k--;) {
            cqs_.push_back(new CompletionQueue());
        }

        // Load users
        std::default_random_engine e(time(0));
        std::uniform_int_distribution<uint64_t> unidis;
        std::unordered_set<uint64_t> unique_addrs;
        while (unique_addrs.size() < user_num) {
            unique_addrs.insert(unidis(e));
        }
        for (auto unique_addr : unique_addrs) {
            users_.push_back(unique_addr);
            dd_ids_.push_back(uint128_t(unidis(e), unidis(e)));
        }
        logging.info("Generate " + std::to_string(users_.size()) + " users");

        // Load network info
        std::ifstream in_ncf(network_filename);
        if (in_ncf.fail()) {
            throw std::logic_error("File is not exist!");
        }
        nlohmann::json js_ncf;
        in_ncf >> js_ncf;
        logging.info("Load network config from: " + network_filename);

        // Add connect to load balancer
        for (auto& addr : js_ncf["bnode_addr"]) {
            add_connect2bnode(addr);
        }

        tp_base_ = std::chrono::system_clock::now();
    }

    void start_round(size_t round_num) {
        // logging.info("Start loop");
        auto prev_tp = std::chrono::system_clock::now();
        std::deque<int64_t> round_cost;
        std::deque<int64_t> round_latency_99th;
        std::deque<int64_t> round_latency_100th;

        for (size_t r = 1;r <= round_num;++r) {
            logging.info("Start " + std::to_string(r) + " round [1.client send]");

            std::unordered_map<uint8_t, uint64_t> mapping_enodeid_counter;
            for (size_t enode_id = 0;enode_id < connections_bnode_.size();++enode_id) {
                mapping_enodeid_counter[enode_id] = 0;
            }
            std::mutex counter_mtx;

            size_t parallel_num = cqs_.size();
            float chip = 1.f * users_.size() / parallel_num;
            std::vector<std::thread> threads;
            for (size_t idx = 0;idx < parallel_num;++idx) {
                threads.emplace_back([=, &mapping_enodeid_counter, &counter_mtx] {
                    // Random setting
                    std::random_device r;
                    std::default_random_engine e{ r() };
                    std::uniform_int_distribution<uint8_t> unidis_enode(0, connections_bnode_.size() - 1);
                    std::uniform_int_distribution<size_t> unidis_tp(0, 3);  // TODO
                    e.seed(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now() - tp_base_).count() + idx * (idx + 1) + idx);

                    for (size_t k = std::floor(idx * chip);k < std::floor((idx + 1) * chip);++k) {
                        PktHead pkt_head;
                        // uint8_t random_enode = unidis_enode(e);  // TODO
                        uint8_t random_enode = k % connections_bnode_.size();  // TODO

                        counter_mtx.lock();
                        mapping_enodeid_counter[random_enode] += 1;
                        counter_mtx.unlock();

                        pkt_head.enode_id = random_enode;
                        pkt_head.from_S = users_[k];
                        if (k % 5 == 0) {  // swap among three users
                            pkt_head.dd_id = dd_ids_[(k + 2) % users_.size()];
                            // pkt_head.to_R = users_[(k + 2) % users_.size()];
                        }
                        else if (k % 5 == 1) {  // swap among three users
                            pkt_head.dd_id = dd_ids_[(k + 1) % users_.size()];
                            // pkt_head.to_R = users_[(k + 1) % users_.size()];
                        }
                        else if (k % 5 == 2) {  // swap among three users
                            pkt_head.dd_id = dd_ids_[k];
                            // pkt_head.to_R = users_[(k - 1) < 0 ? (k - 1) + users_.size() : (k - 1)];
                        }
                        else if (k % 5 == 3) {  // send to self
                            pkt_head.dd_id = dd_ids_[k];
                            // pkt_head.to_R = users_[k];
                        }
                        else if (k % 5 == 4) {  // send to the next user without response
                            pkt_head.dd_id = dd_ids_[(k + 1) % users_.size()];
                            // pkt_head.to_R = users_[(k + 1) % users_.size()];
                        }
                        uint8_t pkt_buffer[PKT_SIZE]{};
                        memcpy(pkt_buffer, &pkt_head, sizeof(PktHead));
                        int64_t start_tp = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now() - tp_base_).count();
                        memcpy(pkt_buffer + sizeof(PktHead), &start_tp, sizeof(int64_t));  // add timestamp
                        g_crypto_lib.encrypt(pkt_buffer, PKT_SIZE - MAC_SIZE, pkt_buffer);
                        send_pkt2bnode(random_enode, users_[k], std::string(pkt_buffer, pkt_buffer + PKT_SIZE), idx);  // Test
                    }
                    });
            }
            for (size_t idx = 0;idx < parallel_num;++idx) {
                threads[idx].join();
            }
            for (size_t enode_id = 0;enode_id < connections_bnode_.size();++enode_id) {
                send_end_sig2bnode(enode_id, mapping_enodeid_counter[enode_id]);  // sync-send makes sure send end singal after finishing async-send
            }

            limit_.P(users_.size());
            auto current_tp = std::chrono::system_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(current_tp - prev_tp);
            prev_tp = current_tp;
            // logging.info("Round cost: " + std::to_string(1.f * duration.count() / std::chrono::milliseconds::period::den) + " s");
            round_cost.push_back(duration.count());

            std::sort(latency_.begin(), latency_.end());
            size_t offset_99th = static_cast<size_t>(std::round(latency_.size() * 0.99));
            int64_t latency_sum_99th = std::accumulate(latency_.begin(), latency_.begin() + offset_99th, 0LL);
            int64_t latency_sum_100th = std::accumulate(latency_.begin(), latency_.end(), 0LL);
            round_latency_99th.push_back(latency_sum_99th / offset_99th);
            round_latency_100th.push_back(latency_sum_100th / latency_.size());
            latency_.clear();
        }

        // Print report
        mtx_.lock();
        if (round_latency_99th.size() > 3) {
            round_latency_99th.erase(round_latency_99th.begin(), round_latency_99th.begin() + 3);  // skip 3 rounds
        }
        if (round_latency_100th.size() > 3) {
            round_latency_100th.erase(round_latency_100th.begin(), round_latency_100th.begin() + 3);  // skip 3 rounds
        }
        int64_t round_latency_sum_99th = std::accumulate(round_latency_99th.begin(), round_latency_99th.end(), 0LL);
        int64_t round_latency_sum_100th = std::accumulate(round_latency_100th.begin(), round_latency_100th.end(), 0LL);
        logging.info("99th latency: " + std::to_string(1.f * round_latency_sum_99th / std::chrono::milliseconds::period::den / round_latency_99th.size()) + " s");
        logging.info("100th latency: " + std::to_string(1.f * round_latency_sum_100th / std::chrono::milliseconds::period::den / round_latency_100th.size()) + " s");


        if (round_cost.size() > 3) {  // skip 3 rounds
            round_cost.pop_front();
            round_cost.pop_front();
            round_cost.pop_front();
        }
        uint64_t round_cost_sum = std::accumulate(round_cost.begin(), round_cost.end(), 0LL);
        uint64_t round_cost_mean = round_cost_sum / round_cost.size();
        logging.info("Mean round cost: " + std::to_string(1.f * round_cost_mean / std::chrono::milliseconds::period::den) + " s");
        mtx_.unlock();

        std::cout << "Finish exp" << std::endl;  // end signal for scripts! imported!
    }

    void recv_pkts_from_bnode_mt() {
        for (size_t k = 0;k < cqs_.size();++k) {
            recv_pkts_from_enode_threads_.emplace_back([this, k] { this->recv_pkts_from_bnode_st(k); });
        }
    }

    void join() {
        for (auto& th : recv_pkts_from_enode_threads_) {
            th.join();
        }
    }

private:
    void add_connect2bnode(const std::string& addr) {
        connections_bnode_.emplace_back(BoomerangService::NewStub(grpc::CreateChannel(addr, grpc::InsecureChannelCredentials())));
        logging.info("Add load balancer connection " + addr);
    }

    void send_pkt2bnode(size_t id, uint64_t ip, const std::string& pkt, size_t cq_id) {
        PayloadWithRes request;
        request.set_reserved(ip);
        request.set_data(pkt);

        AsyncClientCall* call = new AsyncClientCall;

        call->response_reader = connections_bnode_[id]->PrepareAsyncSendMsg(&call->context, request, &(*cqs_[cq_id]));

        call->response_reader->StartCall();

        call->response_reader->Finish(&call->reply, &call->status, (void*)call);
    }

    void send_end_sig2bnode(size_t id, size_t counter) {
        PayloadWithRes request;
        Payload response;
        request.set_reserved(0);
        request.set_data(std::to_string(counter));

        AsyncClientCall* call = new AsyncClientCall;

        call->response_reader = connections_bnode_[id]->PrepareAsyncSendMsg(&call->context, request, &(*cqs_[0]));

        call->response_reader->StartCall();

        call->response_reader->Finish(&call->reply, &call->status, (void*)call);
    }

    void recv_pkts_from_bnode_st(size_t cq_id) {
        void* got_tag;
        bool ok = false;
        bool failed_flag = false;
        uint8_t pkt_buffer[PKT_SIZE - MAC_SIZE];
        while ((*cqs_[cq_id]).Next(&got_tag, &ok)) {
            AsyncClientCall* call = static_cast<AsyncClientCall*>(got_tag);

            GPR_ASSERT(ok);

            if (!call->status.ok()) {
                if (!failed_flag) {
                    logging.error(call->status.error_message() + " : " + std::to_string(call->status.error_code()));
                    logging.error("RPC failed");
                }
                failed_flag = true;
                delete call;
                continue;
            }

            if (call->reply.data().size() == 0) {  // skip end signal return pkt
                delete call;
                continue;
            }

            if (call->reply.data().size() == 1) { // dedup pkt
                limit_.V();
                delete call;
                continue;
            }

            uint8_t* p = reinterpret_cast<uint8_t*>(const_cast<char*>(call->reply.data().data()));
            g_crypto_lib.decrypt(p, PKT_SIZE, pkt_buffer);
            int64_t start_tp;
            memcpy(&start_tp, pkt_buffer + sizeof(PktHead), sizeof(int64_t));
            int64_t end_tp = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now() - tp_base_).count();

            mtx_.lock();
            latency_.push_back(end_tp - start_tp);
            mtx_.unlock();

            limit_.V();
            delete call;
        }
    }
};

#include "docopt.h"
static const char USAGE[] =
R"(
    Usage:
      exec [--id <id>] [-u <user_num>] [-r <round_num>] [-p <parallel_num>] [-c <config_path>]

    Options:
      -h --help                           Show this screen.
      --version                           Show version.
      --id <id>                           Id of client [default: 0]
      -u --user-num <user_num>            Num of simulated users [default: 100]
      -r --round-num <round_num>          Num of synchronized rounds [default: 10]
      -p --parallel-num <parallel_num>    Parallel num of grpc recv [default: 1]
      -c --config-path <config_path>      Path of the network config file [default: ../config/config_local.json]
)";

#include <unistd.h>  // usleep
#include <bitset>

int main(int argc, char** argv)
{
    std::map<std::string, docopt::value> docopt_args = docopt::docopt(
        USAGE,
        { argv + 1, argv + argc },
        true,  // show help if requested
        "Boomerang Test Client");  // version string

    logging.set_id_prefix(docopt_args["--id"].asLong(), "TestClient");

    logging.info("Input args:");
    std::string args_str = "";
    for (auto arg : docopt_args) {
        args_str += arg.first + " " + arg.second.asString() + "; ";
    }
    logging.info(args_str);

    BoomerangTestClient boomerang_tc(docopt_args["--id"].asLong(), docopt_args["--user-num"].asLong(), docopt_args["--parallel-num"].asLong(), docopt_args["--config-path"].asString());

    boomerang_tc.recv_pkts_from_bnode_mt();
    boomerang_tc.start_round(docopt_args["--round-num"].asLong());

    boomerang_tc.join();  //blocks forever
    return 0;
}