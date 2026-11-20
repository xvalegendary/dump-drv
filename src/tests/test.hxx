#pragma once

#include <functional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace test {

struct Case {
    std::string suite;
    std::string name;
    std::function<void()> run;
};

inline std::vector<Case>& registry() {
    static std::vector<Case> cases;
    return cases;
}

struct Registration {
    Registration(std::string suite, std::string name, std::function<void()> run) {
        registry().push_back(Case{std::move(suite), std::move(name), std::move(run)});
    }
};

inline void require(bool condition, std::string_view expression) {
    if (!condition) {
        throw std::runtime_error(std::string(expression));
    }
}

template <typename Actual, typename Expected>
void require_equal(const Actual& actual, const Expected& expected, std::string_view expression) {
    if (!(actual == expected)) {
        throw std::runtime_error(std::string(expression) + " actual=" + std::to_string(static_cast<unsigned long long>(actual)) + " expected=" + std::to_string(static_cast<unsigned long long>(expected)));
    }
}

}

#define TEST_CASE(suite_name, case_name) \
    static void case_name(); \
    static test::Registration registration_##case_name{suite_name, #case_name, case_name}; \
    static void case_name()

#define REQUIRE(expression) test::require(static_cast<bool>(expression), #expression)
#define REQUIRE_EQUAL(actual, expected) test::require_equal((actual), (expected), #actual " == " #expected)
