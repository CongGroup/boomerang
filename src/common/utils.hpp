#pragma once

#include <iostream>
#include <mutex>
#include <condition_variable>

class Semaphore {
private:
    int count;
    std::mutex mtk;
    std::condition_variable cv;
public:
    Semaphore() : count(0) {}
    Semaphore(int c) : count(c) {}

    void P() {
        std::unique_lock<std::mutex> lck(mtk);
        if (--count < 0)
            cv.wait(lck);
    }  // wait

    void V() {
        std::unique_lock<std::mutex> lck(mtk);
        if (++count <= 0)
            cv.notify_one();
    }  // signal

    int get_count() {
        return count;
    }

    void set_count(int c) {
        count = c;
    }
};

class Limit {
private:
    int count;
    std::mutex mtk;
    std::condition_variable cv;
public:
    Limit() : count(0) {}
    Limit(int c) : count(c) {}

    void P(int needed) {
        std::unique_lock<std::mutex> lck(mtk);
        count -= needed;
        if (count < 0) {
            cv.wait(lck);
        }
    }  // wait

    void V() {
        std::unique_lock<std::mutex> lck(mtk);
        if (++count == 0) {
            // count = 0;
            cv.notify_one();
        }
    }  // signal

    int get_count() {
        return count;
    }

    void set_count(int c) {
        count = c;
    }
};

#include <cstring>
#include <stdint.h>

// class Pkt {
// private:
//     uint8_t* data_;
//     size_t size_;

// public:
//     Pkt(size_t size) : size_(size), data_(new uint8_t[size]) {
//     }

//     Pkt(size_t size, const char* data) : size_(size), data_(new uint8_t[size]) {
//         memcpy(data_, data, size_);
//     }

//     /* Copy semantics */
//     Pkt(const Pkt& other) {
//         size_t size = other.get_size();
//         size_ = size;
//         data_ = new uint8_t[size];
//         std::copy(other.data_, other.data_ + size, data_);
//     }
//     Pkt& operator=(const Pkt& other) {
//         if (this != &other)
//         {
//             delete[] data_;
//             size_t size = other.get_size();
//             size_ = size;
//             data_ = new uint8_t[size];
//             std::copy(other.data_, other.data_ + size, data_);
//         }
//         return *this;
//     }

//     ~Pkt() {
//         delete[] data_;
//     }

//     void write_data(const uint8_t* src) {
//         memcpy(data_, src, size_);
//     }

//     void read_data(uint8_t* dst) {
//         memcpy(dst, data_, size_);
//     }

//     void write_random_data() {
//         memset(data_, 0, size_);
//     }

//     void write_ip(uint64_t ip) {
//         memcpy(data_, &ip, sizeof(uint64_t));
//     }

//     uint8_t* get_data() {
//         return data_;
//     }

//     size_t get_size() const {
//         return size_;
//     }
// };

#include <vector>
#include <string>

void split_string(const std::string& s, std::vector<std::string>& v, const std::string& c)
{
    v.clear();
    std::string::size_type pos1, pos2;
    pos2 = s.find(c);
    pos1 = 0;
    while (std::string::npos != pos2)
    {
        v.push_back(s.substr(pos1, pos2 - pos1));

        pos1 = pos2 + c.size();
        pos2 = s.find(c, pos1);
    }
    if (pos1 != s.length())
        v.push_back(s.substr(pos1));
}

uint64_t encode_ipANDport(const std::string& ip, uint16_t port)
{
    std::vector<std::string> v;
    split_string(ip, v, ".");
    uint64_t ret = 0x0000000000000000;
    for (size_t i = 0; i < 4; ++i)
    {
        ret ^= static_cast<uint8_t>(atol(v[i].c_str()));
        ret = ret << 8;
    }
    ret = ret << 8;
    ret ^= port;
    ret = ret << 16;
    // ret ^= server_port;
    return ret;
}

void decode_ipANDport(uint64_t ipANDport, std::string* ip, uint16_t* port)
{
    std::vector<std::string> v;
    *port = static_cast<uint16_t>(ipANDport >> 16);
    for (size_t i = 0; i < 4; ++i)
    {
        v.push_back(std::to_string(static_cast<uint8_t>(ipANDport >> (32 + i * 8))));
    }
    *ip = v[3] + "." + v[2] + "." + v[1] + "." + v[0];
}

class LogHelper {
private:
    size_t id_;
    std::string prefix_;
public:
    LogHelper() : id_(0), prefix_("Null") {
    }

    void set_id_prefix(size_t id, const std::string& prefix) {
        id_ = id;
        prefix_ = prefix;
    }

    void info(const std::string& str) {
        std::cout << "[" << prefix_ << " " << id_ << "] " << str << std::endl;
    }

    void error(const std::string& str) {
        std::cerr << "[" << prefix_ << " " << id_ << "] " << str << std::endl;
    }
};


#include <arpa/inet.h>
#include <cerrno>
#include <ifaddrs.h>
#include <net/if.h>
#include <string.h>
#include <sysexits.h>
#include <sys/socket.h>
#include <sys/types.h>

std::string get_port(const std::string& addr) {
    std::vector<std::string> v;
    split_string(addr, v, ":");
    return v.back();
}

std::string get_loopback_addr(const std::string& addr) {
    std::vector<std::string> v;
    split_string(addr, v, ":");
    return "127.0.0.1:" + v.back();
}

std::string get_interface_ip(const std::string& interface_name) {
    struct ifaddrs* ptr_ifaddrs = nullptr;

    auto result = getifaddrs(&ptr_ifaddrs);
    if (result != 0) {
        std::cout << "`getifaddrs()` failed: " << strerror(errno) << std::endl;
        return "127.0.0.1";
    }

    for (struct ifaddrs* ptr_entry = ptr_ifaddrs;ptr_entry != nullptr;ptr_entry = ptr_entry->ifa_next) {
        std::string ipaddress_human_readable_form;
        std::string netmask_human_readable_form;

        if (std::string(ptr_entry->ifa_name) != interface_name) {
            continue;
        }
        sa_family_t address_family = ptr_entry->ifa_addr->sa_family;
        if (address_family == AF_INET) {
            // IPv4

            // Be aware that the `ifa_addr`, `ifa_netmask` and `ifa_data` fields might contain nullptr.
            // Dereferencing nullptr causes "Undefined behavior" problems.
            // So it is need to check these fields before dereferencing.
            if (ptr_entry->ifa_addr != nullptr) {
                char buffer[INET_ADDRSTRLEN] = { 0, };
                inet_ntop(
                    address_family,
                    &((struct sockaddr_in*)(ptr_entry->ifa_addr))->sin_addr,
                    buffer,
                    INET_ADDRSTRLEN
                );

                ipaddress_human_readable_form = std::string(buffer);
            }
            freeifaddrs(ptr_ifaddrs);
            return ipaddress_human_readable_form;
        }
    }
    std::cout << "No match interface name" << std::endl;
    freeifaddrs(ptr_ifaddrs);
    return "127.0.0.1";
}

std::string uninitialized_string(size_t size) {
    std::string ret;
    ret.resize(size);
    return ret;
}