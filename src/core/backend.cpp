#include "includes.h"
#include "backend.hpp"

#include "crypto/bytes.hpp"
#include "crypto/keychain.hpp"
#include "encoding/base64.hpp"
#include "encoding/read.hpp"
#include "encoding/write.hpp"
#include "net/http.hpp"
#include "os/system.hpp"

using core::RelayStats;
using crypto::KEY_SIZE;
using util::Second;

namespace core
{
  using namespace std::chrono_literals;

  const char* RELAY_VERSION = "1.4.0";

  const char* const UPDATE_ENDPOINT = "/relay_update";

  const double UPDATE_TIMEOUT_SECS = 30.0;
  const double CLEAN_SHUTDOWN_TIMEOUT_SECS = 60.0;

  auto UpdateRequest::from(const std::vector<uint8_t>& v) -> bool
  {
    size_t index = 0;
    if (!encoding::read_uint32(v, index, this->version)) {
      return false;
    }
    if (!encoding::read_string(v, index, this->address)) {
      return false;
    }
    if (!encoding::read_bytes(v, index, public_key, public_key.size())) {
      return false;
    }
    if (!encoding::read_uint32(v, index, this->ping_stats.num_relays)) {
      return false;
    }

    for (size_t i = 0; i < ping_stats.num_relays; i++) {
      if (!encoding::read_uint64(v, index, this->ping_stats.ids[i])) {
        return false;
      }
      if (!encoding::read_bytes(
           v.data(), v.size(), index, reinterpret_cast<uint8_t*>(&ping_stats.rtt[i]), sizeof(float), sizeof(float))) {
        return false;
      }
      if (!encoding::read_bytes(
           v.data(), v.size(), index, reinterpret_cast<uint8_t*>(&ping_stats.jitter[i]), sizeof(float), sizeof(float))) {
        return false;
      }
      if (!encoding::read_bytes(
           v.data(), v.size(), index, reinterpret_cast<uint8_t*>(&ping_stats.packet_loss[i]), sizeof(float), sizeof(float))) {
        return false;
      }
    }

    if (!encoding::read_uint64(v, index, this->session_count)) {
      return false;
    }
    if (!encoding::read_uint64(v, index, this->envelope_up)) {
      return false;
    }
    if (!encoding::read_uint64(v, index, this->envelope_down)) {
      return false;
    }
    if (!encoding::read_uint64(v, index, this->outbound_ping_tx)) {
      return false;
    }
    if (!encoding::read_uint64(v, index, this->route_request_rx)) {
      return false;
    }
    if (!encoding::read_uint64(v, index, this->route_request_tx)) {
      return false;
    }
    if (!encoding::read_uint64(v, index, this->route_response_rx)) {
      return false;
    }
    if (!encoding::read_uint64(v, index, this->route_response_tx)) {
      return false;
    }
    if (!encoding::read_uint64(v, index, this->client_to_server_rx)) {
      return false;
    }
    if (!encoding::read_uint64(v, index, this->client_to_server_tx)) {
      return false;
    }
    if (!encoding::read_uint64(v, index, this->server_to_client_rx)) {
      return false;
    }
    if (!encoding::read_uint64(v, index, this->server_to_client_tx)) {
      return false;
    }
    if (!encoding::read_uint64(v, index, this->inbound_ping_rx)) {
      return false;
    }
    if (!encoding::read_uint64(v, index, this->inbound_ping_tx)) {
      return false;
    }
    if (!encoding::read_uint64(v, index, this->pong_rx)) {
      return false;
    }
    if (!encoding::read_uint64(v, index, this->session_ping_rx)) {
      return false;
    }
    if (!encoding::read_uint64(v, index, this->session_ping_tx)) {
      return false;
    }
    if (!encoding::read_uint64(v, index, this->session_pong_rx)) {
      return false;
    }
    if (!encoding::read_uint64(v, index, this->session_pong_tx)) {
      return false;
    }
    if (!encoding::read_uint64(v, index, this->continue_request_rx)) {
      return false;
    }
    if (!encoding::read_uint64(v, index, this->continue_request_tx)) {
      return false;
    }
    if (!encoding::read_uint64(v, index, this->continue_response_rx)) {
      return false;
    }
    if (!encoding::read_uint64(v, index, this->continue_response_tx)) {
      return false;
    }
    if (!encoding::read_uint64(v, index, this->near_ping_rx)) {
      return false;
    }
    if (!encoding::read_uint64(v, index, this->near_ping_tx)) {
      return false;
    }
    if (!encoding::read_uint64(v, index, this->unknown_rx)) {
      return false;
    }
    uint8_t shutdown_flag;
    if (!encoding::read_uint8(v, index, shutdown_flag)) {
      return false;
    }
    this->shutting_down = static_cast<bool>(shutdown_flag);

    if (!encoding::read_double(v, index, this->cpu_usage)) {
      return false;
    }

    if (!encoding::read_double(v, index, this->mem_usage)) {
      return false;
    }

    return true;
  }

  auto UpdateResponse::size() -> size_t
  {
    size_t size = 4 + 8 + 4 + this->num_relays * (8 + 4);

    for (size_t i = 0; i < this->num_relays; i++) {
      // only used in tests, so being lazy here;
      const auto& relay = relays[i];
      size += relay.address.to_string().length();
    }

    return size;
  }

  // only used in tests
  auto UpdateResponse::into(std::vector<uint8_t>& v) -> bool
  {
    size_t index = 0;

    if (!encoding::write_uint32(v, index, this->version)) {
      LOG(TRACE, "could not write version");
      return false;
    }

    if (!encoding::write_uint64(v, index, this->timestamp)) {
      LOG(TRACE, "could not write timestamp");
      return false;
    }

    if (!encoding::write_uint32(v, index, this->num_relays)) {
      LOG(TRACE, "could not write num relays");
      return false;
    }

    for (size_t i = 0; i < this->num_relays; i++) {
      const auto& relay = relays[i];

      if (!encoding::write_uint64(v, index, relay.id)) {
        LOG(TRACE, "could not write relay id");
        return false;
      }

      if (!encoding::write_string(v, index, relay.address.to_string())) {
        LOG(TRACE, "could not write relay address");
        return false;
      }
    }

    return true;
  }

  auto UpdateResponse::from(const std::vector<uint8_t>& v) -> bool
  {
    size_t index = 0;

    if (!encoding::read_uint32(v, index, version)) {
      LOG(ERROR, "unable to read update response version");
      return false;
    }

    if (!encoding::read_uint64(v, index, this->timestamp)) {
      LOG(ERROR, "unable to read update response timestamp");
      return false;
    }

    if (!encoding::read_uint32(v, index, this->num_relays)) {
      LOG(ERROR, "unable to read update response relay count");
      return false;
    }

    for (size_t i = 0; i < this->num_relays; i++) {
      auto& relay = relays[i];
      if (!encoding::read_uint64(v, index, relay.id)) {
        LOG(ERROR, "unable to read update response relay id #", i);
        return false;
      }

      std::string addr;
      if (!encoding::read_string(v, index, addr)) {
        LOG(ERROR, "unable to read update response relay address #", i);
        return false;
      }

      if (!relay.address.parse(addr)) {
        LOG(ERROR, "unable to parse relay address: ", addr);
        return false;
      }
    }

    return true;
  }

  Backend::Backend(
   std::string hostname,
   std::string address,
   const crypto::Keychain& keychain,
   RouterInfo& router_info,
   RelayManager& relay_manager,
   const core::SessionMap& sessions,
   net::CurlWrapper& client)
   : hostname(hostname),
     relay_address(address),
     keychain(keychain),
     router_info(router_info),
     relay_manager(relay_manager),
     session_map(sessions),
     http_client(client)
  {}

  bool Backend::update_loop(
   volatile bool& should_loop,
   const volatile bool& should_clean_shutdown,
   util::ThroughputRecorder& recorder,
   core::SessionMap& sessions)
  {
    bool success = true;

    while (should_loop) {
      // todo: wtf
      // LOG(DEBUG, "should loop = ", should_loop ? "true" : "false");
      switch (update(recorder, false, should_loop)) {
        case UpdateResult::Failure: {
          LOG(ERROR, "could not update relay");
          success = should_loop = false;
        } break;
        default: {
          sessions.purge(this->router_info.current_time<uint64_t>());
          std::this_thread::sleep_for(1s);
        }
      }
    }

    // LOG(DEBUG, "exiting update loop");

    Clock backend_timeout;
    if (should_clean_shutdown) {
      LOG(DEBUG, "starting clean shutdown");
      double time_since_last_update = backend_timeout.elapsed<Second>();
      // should_loop will be false here
      while (update(recorder, true, should_loop) != UpdateResult::Success &&
             time_since_last_update < CLEAN_SHUTDOWN_TIMEOUT_SECS) {
        time_since_last_update = backend_timeout.elapsed<Second>();
        LOG(DEBUG, "time since last update = ", time_since_last_update);
        std::this_thread::sleep_for(1s);
      }

      if (time_since_last_update < 60.0) {
        std::this_thread::sleep_for(30s);
      }
    }

    return success;
  }

  auto Backend::update(util::ThroughputRecorder& recorder, bool shutdown, const volatile bool& should_retry) -> UpdateResult
  {
    std::vector<uint8_t> req, res;

    static bool first_update = true;

    // serialize request
    {
      RelayStats stats;
      this->relay_manager.get_stats(stats);

      const size_t request_size = 4 +                             // request version
                                  4 +                             // address length
                                  this->relay_address.length() +  // address
                                  KEY_SIZE +                      // public key
                                  4 +                             // number of relay ping stats
                                  stats.num_relays * 20 +         // relay ping stats
                                  8 +                             // session count
                                  8 +                             // envelope up
                                  8 +                             // envelope down
                                  8 +                             // outbound ping tx
                                  8 +                             // route request rx
                                  8 +                             // route request tx
                                  8 +                             // route response rx
                                  8 +                             // route response tx
                                  8 +                             // client to server rx
                                  8 +                             // client to server tx
                                  8 +                             // server to client rx
                                  8 +                             // server to client tx
                                  8 +                             // inbound ping rx
                                  8 +                             // inbound ping tx
                                  8 +                             // pong rx
                                  8 +                             // session ping rx
                                  8 +                             // session ping tx
                                  8 +                             // session pong rx
                                  8 +                             // session pong tx
                                  8 +                             // continue request rx
                                  8 +                             // continue request tx
                                  8 +                             // continue response rx
                                  8 +                             // continue response tx
                                  8 +                             // near ping rx
                                  8 +                             // near ping tx
                                  8 +                             // unknown Rx
                                  1 +                             // shut down flag
                                  8 +                             // cpu usage
                                  8 +                             // memory usage
                                  4;                              // relay version length
      req.resize(request_size);

      size_t index = 0;

      encoding::write_uint32(req, index, UPDATE_REQUEST_VERSION);
      encoding::write_string(req, index, this->relay_address);
      encoding::write_bytes(req, index, this->update_token, this->update_token.size());
      encoding::write_uint32(req, index, stats.num_relays);

      for (unsigned int i = 0; i < stats.num_relays; ++i) {
        encoding::write_uint64(req, index, stats.ids[i]);
        encoding::write_bytes(req.data(), req.size(), index, reinterpret_cast<uint8_t*>(&stats.rtt[i]), sizeof(float));
        encoding::write_bytes(req.data(), req.size(), index, reinterpret_cast<uint8_t*>(&stats.jitter[i]), sizeof(float));
        encoding::write_bytes(req.data(), req.size(), index, reinterpret_cast<uint8_t*>(&stats.packet_loss[i]), sizeof(float));
      }

      encoding::write_uint64(req, index, this->session_map.size());
      encoding::write_uint64(req, index, this->session_map.envelope_up_total());
      encoding::write_uint64(req, index, this->session_map.envelope_down_total());

      util::ThroughputRecorder traffic_stats(std::move(recorder));

      encoding::write_uint64(req, index, traffic_stats.outbound_ping_tx.num_bytes.load());

      encoding::write_uint64(req, index, traffic_stats.route_request_rx.num_bytes.load());
      encoding::write_uint64(req, index, traffic_stats.route_request_tx.num_bytes.load());

      encoding::write_uint64(req, index, traffic_stats.route_response_rx.num_bytes.load());
      encoding::write_uint64(req, index, traffic_stats.route_response_tx.num_bytes.load());

      encoding::write_uint64(req, index, traffic_stats.client_to_server_rx.num_bytes.load());
      encoding::write_uint64(req, index, traffic_stats.client_to_server_tx.num_bytes.load());

      encoding::write_uint64(req, index, traffic_stats.server_to_client_rx.num_bytes.load());
      encoding::write_uint64(req, index, traffic_stats.server_to_client_tx.num_bytes.load());

      encoding::write_uint64(req, index, traffic_stats.inbound_ping_rx.num_bytes.load());
      encoding::write_uint64(req, index, traffic_stats.inbound_ping_tx.num_bytes.load());

      encoding::write_uint64(req, index, traffic_stats.pong_rx.num_bytes.load());

      encoding::write_uint64(req, index, traffic_stats.session_ping_rx.num_bytes.load());
      encoding::write_uint64(req, index, traffic_stats.session_ping_tx.num_bytes.load());

      encoding::write_uint64(req, index, traffic_stats.session_pong_rx.num_bytes.load());
      encoding::write_uint64(req, index, traffic_stats.session_pong_tx.num_bytes.load());

      encoding::write_uint64(req, index, traffic_stats.continue_request_rx.num_bytes.load());
      encoding::write_uint64(req, index, traffic_stats.continue_request_tx.num_bytes.load());

      encoding::write_uint64(req, index, traffic_stats.continue_response_rx.num_bytes.load());
      encoding::write_uint64(req, index, traffic_stats.continue_response_tx.num_bytes.load());

      encoding::write_uint64(req, index, traffic_stats.near_ping_rx.num_bytes.load());
      encoding::write_uint64(req, index, traffic_stats.near_ping_tx.num_bytes.load());

      encoding::write_uint64(req, index, traffic_stats.unknown_rx.num_bytes.load());

      encoding::write_uint8(req, index, shutdown);

#if defined(linux) || defined(__linux) || defined(__linux__)

      auto sys_stats = os::GetUsage();
      encoding::write_double(req, index, sys_stats.cpu);
      encoding::write_double(req, index, sys_stats.mem);

#else // #if defined(linux) || defined(__linux) || defined(__linux__)

      encoding::write_double(req, index, 0.0);
      encoding::write_double(req, index, 0.0);

#endif // #if defined(linux) || defined(__linux) || defined(__linux__)
    }

    // LOG(DEBUG, "sending request");
    util::Clock timeout;
    double elapsed_seconds = timeout.elapsed<Second>();
    size_t num_retries = 0;
    bool request_success = false;
    while (!(request_success = this->http_client.send_request(this->hostname, UPDATE_ENDPOINT, req, res)) && should_retry &&
           num_retries < MAX_UPDATE_ATTEMPTS && elapsed_seconds < UPDATE_TIMEOUT_SECS) {
      LOG(ERROR, "relay update failed ", num_retries);
      num_retries++;
      std::this_thread::sleep_for(1s);
    }

    if (num_retries >= MAX_UPDATE_ATTEMPTS) {
      return UpdateResult::Failure;
    }

    if (!request_success) {
      return UpdateResult::Failure;
    }

    // early return if shutting down since the response won't be valid
    if (shutdown) {
      return UpdateResult::Success;
    }

    // todo
    // LOG(DEBUG, "parsing response");

    // parse response
    {
      UpdateResponse response;
      if (!response.from(res)) {
        LOG(ERROR, "could not deserialize update response, response size = ", res.size());
        return UpdateResult::Failure;
      }

      if (response.version != UPDATE_RESPONSE_VERSION) {
        LOG(ERROR, "bad relay version response version. expected ", UPDATE_RESPONSE_VERSION, ", got ", response.version);
        return UpdateResult::Failure;
      }

      this->router_info.set_timestamp(response.timestamp);

      if (response.num_relays > MAX_RELAYS) {
        LOG(ERROR, "too many relays to ping. max is ", MAX_RELAYS, ", got ", response.num_relays, '\n');
        return UpdateResult::Failure;
      }

      if (!this->relay_manager.update(response.num_relays, response.relays)) {
        LOG(ERROR, "could not update relay manager");
        return UpdateResult::Failure;
      }
    }

    // todo
    // LOG(DEBUG, "updated relay");

    if (first_update)
    {
      LOG(INFO, "relay initialized");
      first_update = false;
    }

    return UpdateResult::Success;
  }
}  // namespace core
