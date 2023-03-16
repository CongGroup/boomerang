#include "Enclave_t.h"

#include "sgx_trts.h"
#include <sgx_thread.h>
#include <sgx_spinlock.h>

#include <stdlib.h>
#include <string.h>
#include <vector>
#include <deque>
#include <map>
#include <assert.h>
#include <math.h>
#include <algorithm>
#include <unordered_map>
#include <unordered_set>
#include <string>
#include <bitset>

#include "utils_t.h"
#include "cryptolib.h"
#include "../../../thirdparty/rise/par_obl_primitives.h"
#include "../../common/ds.hpp"

class Enclave
{
private:
    bool is_first_round_ = true;
    std::vector<Pkt> pkts_;
    size_t recv_counter_ = 0;
    size_t send_counter_ = 0;

    size_t worker_thread_num_ = 0;
    enum class WorkerFn {
        ddid_sort,
        toR_sort,
        stop,
    };
    struct worker_state {
        WorkerFn fn;
        int n_done;
        int curr_iter = 0;
    };
    std::mutex mtx_;
    std::condition_variable cv_;
    worker_state state_;

public:
    Enclave() {

    }
    ~Enclave() {
    }

    struct DDIDSorter {
        bool operator()(const Pkt& a, const Pkt& b) {
            bool pred = ObliviousEqual(a.head.dd_id.high, b.head.dd_id.high);
            uint64_t a_64 = ObliviousChoose(pred, a.head.dd_id.low, a.head.dd_id.high);
            uint64_t b_64 = ObliviousChoose(pred, b.head.dd_id.low, b.head.dd_id.high);
            return ObliviousLess(a_64, b_64);
        }
    };

    struct TORSorter {
        bool operator()(const Pkt& a, const Pkt& b) {
            return ObliviousLess(a.head.to_R, b.head.to_R);
        }
    };

    std::string uninitialized_string(size_t size) {
        std::string ret;
        ret.resize(size);
        return ret;
    }

    inline bool ObliviousEqual128(uint128_t a, uint128_t b) {
        return ObliviousEqual(a.high, b.high) && ObliviousEqual(a.low, b.low);
    }


    void DDR(uint8_t** in_data, size_t batch_num, size_t pkt_size, std::vector<Pkt>& pkts) {
        pkts.clear();
        uint8_t pkt_buffer[pkt_size - MAC_SIZE];
        std::unordered_set<uint64_t> dedup_set;
        for (size_t i = 0;i < batch_num;++i) {
            // cal pkt digest
            uint64_t digest = 0;
            uint64_t tmp = 0;
            for (size_t j = 0;j < pkt_size;++j) {
                tmp |= in_data[i][j];
                tmp = tmp << 8;
                if (j % 8 == 0 || j == pkt_size - 1) {
                    digest ^= tmp;
                    tmp = 0;
                }
            }

            // decrypt and add pkt that is not in the set
            if (dedup_set.find(digest) == dedup_set.end()) {
                dedup_set.insert(digest);
                g_crypto_lib.decrypt(in_data[i], pkt_size, pkt_buffer);
                pkts.push_back(Pkt(pkt_buffer, pkt_size - MAC_SIZE));
            }
            else {
                eprintf("dedup+1 ");
            }
        }
    }

    void handle_batch(uint8_t** in_data, size_t batch_num, size_t pkt_size, uint8_t* out_data, size_t* valid_out_data_size) {
        if (is_first_round_) {
            pkts_.reserve(static_cast<size_t>(1.2 * batch_num));
            is_first_round_ = false;
        }
        try
        {
            // Dedup, decrypt and restore pkt
            DDR(in_data, batch_num, pkt_size, pkts_);

            // Osort
            if (worker_thread_num_ == 1) {
                ObliviousSort(pkts_.begin(), pkts_.end(), DDIDSorter());
            }
            else {
                notify_workers(WorkerFn::ddid_sort);
                ObliviousSortParallelNonAdaptive(pkts_.begin(), pkts_.end(), DDIDSorter(), worker_thread_num_, 0);
                wait_for_workers();
            }

            // Dedup, set to_R, correct and swap
            for (size_t k = 0;k < pkts_.size();++k) {
                pkts_[k].head.to_R = pkts_[k].head.from_S;
            }
            // pkts_.push_front(Pkt());
            pkts_.push_back(Pkt());
            for (size_t k = 0;k < pkts_.size() - 1;++k) {
                bool is_same_as_prev = ObliviousEqual128(pkts_[k].head.dd_id, pkts_[k - 1].head.dd_id);
                bool is_same_as_next = ObliviousEqual128(pkts_[k].head.dd_id, pkts_[k + 1].head.dd_id);
                bool is_swap = !is_same_as_prev & is_same_as_next;
                uint8_t tmp = ObliviousChoose<uint8_t>(is_swap, pkts_[k].head.enode_id, 0);
                pkts_[k].head.enode_id = ObliviousChoose<uint8_t>(is_swap, pkts_[k + 1].head.enode_id, pkts_[k].head.enode_id);
                pkts_[k + 1].head.enode_id = ObliviousChoose<uint8_t>(is_swap, tmp, pkts_[k + 1].head.enode_id);
                pkts_[k].head.to_R = ObliviousChoose<uint64_t>(is_swap, pkts_[k + 1].head.from_S, pkts_[k].head.to_R);
                pkts_[k + 1].head.to_R = ObliviousChoose<uint64_t>(is_swap, pkts_[k].head.from_S, pkts_[k + 1].head.to_R);
            }
            pkts_.pop_back();
            // pkts_.pop_front();


            // Osort
            if (worker_thread_num_ == 1) {
                ObliviousSort(pkts_.begin(), pkts_.end(), TORSorter());
            }
            else {
                notify_workers(WorkerFn::toR_sort);
                ObliviousSortParallelNonAdaptive(pkts_.begin(), pkts_.end(), TORSorter(), worker_thread_num_, 0);
                wait_for_workers();
            }

            // Copy out
            uint8_t pkt_buffer[pkt_size - MAC_SIZE];
            uint8_t* out_data_p = out_data;
            for (size_t k = 0;k < pkts_.size();++k) {
                memcpy(pkt_buffer, &pkts_[k], pkt_size - MAC_SIZE);
                memcpy(out_data_p, pkt_buffer + sizeof(uint64_t) * 2, sizeof(uint64_t));
                g_crypto_lib.encrypt(pkt_buffer, pkt_size - MAC_SIZE, out_data_p + sizeof(uint64_t));
                out_data_p += pkt_size + sizeof(uint64_t);
            }
            *valid_out_data_size = pkts_.size();
        }
        catch (const std::exception& e)
        {
            eprintf("Enclave error: %s\n", e.what());
        }
    }

    void set_worker_thread_num(size_t worker_thread_num) {
        worker_thread_num_ = worker_thread_num;
    }

    void start_worker_loop(size_t thread_id) {
        int next_iter = 1;
        while (true) {
            std::unique_lock<std::mutex> lk(mtx_);
            cv_.wait(lk, [&, this, next_iter, thread_id] {
                bool ready = state_.curr_iter == next_iter;
                return ready;
                });
            lk.unlock();
            if (state_.fn == WorkerFn::ddid_sort) {
                ObliviousSortParallelNonAdaptive(pkts_.begin(), pkts_.end(), DDIDSorter(), worker_thread_num_, thread_id);
            }
            else if (state_.fn == WorkerFn::toR_sort) {
                ObliviousSortParallelNonAdaptive(pkts_.begin(), pkts_.end(), TORSorter(), worker_thread_num_, thread_id);
            }
            else if (state_.fn == WorkerFn::stop) {
                return;
            }

            next_iter++;
            lk.lock();
            if (++state_.n_done == worker_thread_num_) {
                lk.unlock();
                cv_.notify_all();
            }

        }
    }

    void notify_workers(WorkerFn fn) {
        {
            std::lock_guard<std::mutex> lk(mtx_);
            state_.fn = fn;
            state_.curr_iter++;
            state_.n_done = 1;
        }
        cv_.notify_all();
    }

    void wait_for_workers() {
        {
            std::unique_lock<std::mutex> lk(mtx_);
            cv_.wait(lk, [&, this] {
                bool done = state_.n_done == worker_thread_num_;
                return done;
                });
        }
    }

};
Enclave enclave;

void ecall_handle_batch(uint8_t** in_data, size_t batch_num, size_t pkt_size, uint8_t* out_data, size_t out_data_size, size_t* valid_out_data_size) {
    enclave.handle_batch(in_data, batch_num, pkt_size, out_data, valid_out_data_size);
}

void ecall_set_worker_thread_num(size_t worker_thread_num) {
    enclave.set_worker_thread_num(worker_thread_num);
}

void ecall_start_worker_loop(size_t thread_id) {
    enclave.start_worker_loop(thread_id);
}
