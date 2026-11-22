#include "test.hxx"

#include "shared/http.hxx"

#include <cstring>
#include <string>

namespace {

using namespace dump;

const unsigned char* bytes(const std::string& text) {
    return reinterpret_cast<const unsigned char*>(text.data());
}

std::string text_of(const protocol::FixedArray<char, protocol::http_host_size>& value) {
    return std::string(value.data());
}

std::string target_of(const protocol::HttpRecord& record) {
    return std::string(record.target.data());
}

std::string method_of(const protocol::HttpRecord& record) {
    return std::string(record.method.data());
}

}

TEST_CASE("http", http_parses_post_with_headers_and_body) {
    const std::string request = "POST /api/v1/auth HTTP/1.1\r\nHost: api.loader.dev\r\nUser-Agent: Loader/1.2\r\nContent-Length: 12\r\n\r\nkey=abc12345";
    protocol::HttpRecord records[4]{};
    const auto count = http::parse(bytes(request), request.size(), records, 4);
    REQUIRE(count == 1);
    REQUIRE(method_of(records[0]) == "POST");
    REQUIRE(target_of(records[0]) == "/api/v1/auth");
    REQUIRE(text_of(records[0].host) == "api.loader.dev");
    REQUIRE(std::string(records[0].agent.data()) == "Loader/1.2");
    REQUIRE(records[0].headers == 3);
    REQUIRE(records[0].body_length == 12);
    REQUIRE(std::strcmp(records[0].body.data(), "key=abc12345") == 0);
}

TEST_CASE("http", http_parses_get_without_body) {
    const std::string request = "GET /panel/check?user=x HTTP/1.0\r\nHost: 1.2.3.4\r\n\r\n";
    protocol::HttpRecord records[4]{};
    const auto count = http::parse(bytes(request), request.size(), records, 4);
    REQUIRE(count == 1);
    REQUIRE(method_of(records[0]) == "GET");
    REQUIRE(target_of(records[0]) == "/panel/check?user=x");
    REQUIRE(text_of(records[0].host) == "1.2.3.4");
    REQUIRE(records[0].body_length == 0);
}

TEST_CASE("http", http_rejects_lookalike_text) {
    const std::string request = "TARGET /x HTTP/1.1\r\nHost: a\r\n\r\n";
    protocol::HttpRecord records[4]{};
    REQUIRE(http::parse(bytes(request), request.size(), records, 4) == 0);
    const std::string bare = "GET /x nothing-here\r\nHost: a\r\n\r\n";
    REQUIRE(http::parse(bytes(bare), bare.size(), records, 4) == 0);
    const std::string relative = "GET not-a-target HTTP/1.1\r\nHost: a\r\n\r\n";
    REQUIRE(http::parse(bytes(relative), relative.size(), records, 4) == 0);
}

TEST_CASE("http", http_accepts_absolute_target_and_deduplicates) {
    const std::string request = "GET https://cdn.example/x HTTP/1.1\r\nHost: cdn.example\r\n\r\nGET https://cdn.example/x HTTP/1.1\r\nHost: cdn.example\r\n\r\n";
    protocol::HttpRecord records[4]{};
    const auto count = http::parse(bytes(request), request.size(), records, 4);
    REQUIRE(count == 1);
    REQUIRE(target_of(records[0]) == "https://cdn.example/x");
}

TEST_CASE("http", http_clamps_body_and_reports_request_length) {
    std::string request = "POST /upload HTTP/1.1\r\nHost: h\r\nContent-Length: 500\r\n\r\n";
    const auto body_offset = request.size();
    request.append(300, 'a');
    protocol::HttpRecord records[4]{};
    const auto count = http::parse(bytes(request), request.size(), records, 4);
    REQUIRE(count == 1);
    REQUIRE(records[0].body_length == protocol::http_body_size - 1);
    REQUIRE(records[0].request_length == body_offset + protocol::http_body_size - 1);
    REQUIRE(http::method_length(records[0]) == 4);
}

TEST_CASE("http", http_requires_terminated_headers) {
    const std::string request = "POST /x HTTP/1.1\r\nHost: a\r\nContent-Length: 4";
    protocol::HttpRecord records[4]{};
    REQUIRE(http::parse(bytes(request), request.size(), records, 4) == 0);
}

TEST_CASE("http", http_deduplicates_by_structure) {
    protocol::HttpRecord left{};
    protocol::HttpRecord right{};
    std::memcpy(left.method.data(), "GET", 3);
    std::memcpy(right.method.data(), "GET", 3);
    std::memcpy(left.target.data(), "/a", 2);
    std::memcpy(right.target.data(), "/a", 2);
    REQUIRE(http::same(left, right));
    std::memcpy(right.target.data(), "/b", 2);
    REQUIRE(!http::same(left, right));
}