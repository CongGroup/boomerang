/*
 * Modifications Copyright 2020 by Secure XGBoost Contributors
 */
#include <iostream>
#include <stdlib.h>
#include "obl_primitives.h"

namespace obl {

// TODO: define this as inline cause segment fault. Need to know why. Is it due
// to |inline| does not work well with |assembly| impl?
bool LessImplDouble(double x, double y) {
  bool result;
  __asm__ volatile(
      "movsd %1, %%xmm0;"
      "movsd %2, %%xmm1;"
      "comisd %%xmm1, %%xmm0;"
      "setb %0;"
      : "=r"(result)
      : "m"(x), "m"(y)
      : "cc");
  return result;
}

bool LessImplFloat(float x, float y) {
    bool result;
    __asm__ volatile(
            "movsd %1, %%xmm0;"
            "movsd %2, %%xmm1;"
            "comiss %%xmm1, %%xmm0;"
            "setb %0;"
            : "=r"(result)
            : "m"(x), "m"(y)
            : "cc");
    return result;
}

}  // namespace obl

/***************************************************************************************
 * Testing
 **************************************************************************************/
struct Generic {
    double x;
    short y;
    double z;

    Generic() = default;

    Generic(double x, short y, double z)
        : x(x), y(y), z(z) {}

    inline bool operator<(const Generic &b) const {
        return (x < b.x);
    }
    inline bool operator<=(const Generic &b) const {
        return (x <= b.x);
    }
    
    static inline bool ogreater(Generic a, Generic b) {
        return ObliviousGreater(a.x, b.x);
    }
};

namespace obl {

template <>
struct less<Generic> {
  bool operator()(const Generic& a, const Generic& b) {
    return a.x < b.x;
  }
};

}

struct Generic_16B {
    double x;
    uint64_t y;

    Generic_16B() = default;

    Generic_16B(double x, uint64_t y)
        : x(x), y(y) {}
};

struct Foo {
    char a;
    char b;
    char c;
};