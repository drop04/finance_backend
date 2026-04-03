#include <pistache/endpoint.h>
#include <pistache/router.h>
#include <pistache/http.h>
#include <pistache/http_headers.h>
#include <nlohmann/json.hpp>
#include <jwt/jwt.hpp>
#include <openssl/sha.h>

#include <iostream>
#include <vector>
#include <string>
#include <map>
#include <set>
#include <mutex>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <chrono>
#include <random>
#include <ctime>
#include <optional>

using json = nlohmann::json;
using namespace Pistache;
using namespace Pistache::Rest;

const std::string JWT_SECRET = "finance_cpp_secret_key";

std::string gen_uuid(){
    static std::mt19937 rng(std::random_device{}());
    std::uniform_int_distribution<int> d(0,15);
    const char* h = "0123456789abcdef";
    std::string u = "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx";
    for(auto& c : u){
        if(c == 'x')
            c = h[d(rng)];
        else if(c == 'y')
            c = h[(d(rng) & 0x3) | 0x8];
    }
    return u;
}

std::string sha256_hex(const std::string& in){
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(in.c_str()), in.size(), hash);
    std::ostringstream ss;
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++){
        ss << std::hex << std::setw(3) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}

std::string now_str(){
    auto t = std::time(nullptr);
    char buff[32];
    std::strftime(buff, sizeof(buff), "%Y-%m-%dT%H:%M:%SZ", std::gmtime(&t));
    return buff;
}

struct User {
    std::string id, username, pw_hash, role, status, created_at;
};

struct Record {
    std::string id, type, category, date, notes, created_by, created_at, updated_at;
    double amount = 0;
    bool deleted = false;
};

std::vector<User> users;
std::vector<Record> records;
std::mutex mtx;

User* find_user_id(const std::string& id){
    for(auto& u : users){
        if(u.id == id){
            return &u;
        }
    }
    return nullptr;
}

User* find_user_name(const std::string& n){
    for(auto& u : users){
        if(u.username == n){
            return &u;
        }
    }
    return nullptr;
}

Record* find_rec(const std::string& id){
    for(auto& r : records){
        if(r.id == id && !r.deleted){
            return &r;
        }
    }
    return nullptr;
}

json ujson(const User& u){
    return {
        {"id", u.id},
        {"username", u.username},
        {"role", u.role},
        {"status", u.status},
        {"created_at", u.created_at}
    };
}

json rjson(const Record& r){
    return {
        {"id", r.id},
        {"amount", r.amount},
        {"type", r.type},
        {"category", r.category},
        {"date", r.date},
        {"notes", r.notes},
        {"created_by", r.created_by},
        {"created_at", r.created_at},
        {"updated_at", r.updated_at}
    };
}

int rlvl(const std::string& s){
    if(s == "admin"){
        return 3;
    }
    if(s == "analyst"){
        return 2;
    }
    if(s == "viewer"){
        return 1;
    }
    return 0;
}

void send(Http::ResponseWriter& resp, int code, const json& body){
    resp.headers().add<Http::Header::ContentType>(MIME(Application, Json));
    resp.send(Http::Code(code), body.dump());
}

std::string make_token(const std::string& id, const std::string& username, const std::string& role){
    jwt::jwt_object obj{
        jwt::params::algorithm("HS256"),
        jwt::params::secret(JWT_SECRET),
        jwt::params::payload({
            {"id", id},
            {"username", username},
            {"role", role}
        })
    };
    obj.add_claim("exp", std::chrono::system_clock::now() + std::chrono::hours(8));
    return obj.signature();
}

struct Token {
    std::string id, username, role;
    bool valid = false;
};

Token verify_token(const std::string& token){
    Token t;
    try{
        std::error_code ec;
        auto obj = jwt::decode(token, jwt::params::algorithms({"HS256"}), ec, jwt::params::secret(JWT_SECRET), jwt::params::verify(true));
        if(ec){
            return t;
        }
        t.id = obj.payload().get_claim_value<std::string>("id");
        t.username = obj.payload().get_claim_value<std::string>("username");
        t.role = obj.payload().get_claim_value<std::string>("role");
        t.valid = true;
    }
    catch(...) {}
    return t;
}

Token get_auth(const Rest::Request& req){
    auto raw = req.headers().tryGetRaw("Authorization");
    if(!raw.has_value()){
        return {};
    }
    std::string hdr = raw.value().value();
    if(hdr.rfind("Bearer", 0) == 0) {
        hdr = hdr.substr(7);
    }
    return verify_token(hdr);
}

void h_health(const Rest::Request&, Http::ResponseWriter resp){
    send(resp, 200, {
        {"status", "ok"},
        {"time", now_str()},
        {"lang", "C++17"}
    });
}

void h_login(const Rest::Request& req, Http::ResponseWriter resp){
    json b;
    try {
        b = json::parse(req.body());
    }
    catch(...){
        send(resp, 400, {
            {"error", "bad JSON"}
        });
        return;
    }
    if(!b.contains("username") || !b.contains("password")){
        send(resp, 400, {
            {"error", "username and password REQUIRED"}
        });
        return;
    }
    std::lock_guard<std::mutex> lk(mtx);
    auto* u = find_user_name(b["username"]);
    if(!u || u->status != "active" || u->pw_hash != sha256_hex(b["password"])){
        send(resp, 200, {
            {"Error", "Invalid Credentials"}
        });
        return;
    }
    send(resp, 200, {
        {"token", make_token(u->id, u->username, u->role)},
        {"user", ujson(*u)}
    });
}

void h_me(const Rest::Request& req, Http::ResponseWriter resp){
    auto t = get_auth(req);
    if(!t.valid){
        send(resp, 401, {
            {"error", "Not Authenticated"}
        });
        return;
    }
    std::lock_guard<std::mutex> lk(mtx);
    auto* u = find_user_id(t.id);
    if(!u){
        send(resp, 404, {
            {"error", "User Not Found"}
        });
        return;
    }
    send(resp, 200, ujson(*u));
}

void h_list_users(const Rest::Request& req, Http::ResponseWriter resp){
    auto t = get_auth(req);
    if(!t.valid){
        send(resp, 401, {
            {"error", "Not Authenticated"}
        });
        return;
    }
    if(t.role != "admin"){
        send(resp, 403, {
            {"error", "Admins only"}
        });
        return;
    }
    std::lock_guard<std::mutex> lk(mtx);
    json arr = json::array();
    for(auto& u : users){
        arr.push_back(ujson(u));
    }
    send(resp, 200, {
        {"users", arr}
    });
}

void h_create_user(const Rest::Request& req, Http::ResponseWriter resp){
    auto t = get_auth(req);
    if(!t.valid){
        send(resp, 401, {
            {"error", "Not Authenticated"}
        });
        return;
    }
    if(t.role != "admin"){
        send(resp, 403, {
            {"error", "Admins only"}
        });
        return;
    }
    json b;
    try{
        b = json::parse(req.body());
    }catch(...){
        send(resp, 400, {
            {"error", "bad JSON"}
        });
        return;
    }

    if(!b.contains("username") || !b.contains("password")){
        send(resp, 400, {
            {"error", "username and password required"}
        });
        return;
    }
    std::string role = b.value("role", "viewer");
    if(role != "admin" && role != "analyst" && role != "viewer"){
        role = "viewer";
    }
    std::lock_guard<std::mutex> lk(mtx);
    if(find_user_name(b["username"])){
        send(resp, 409, {
            {"error", "username taken"}
        });
        return;
    }
    User u{gen_uuid(), b["username"], sha256_hex(b["password"]), role, "active", now_str()};
    users.push_back(u);
    send(resp, 201, {
        {"message", "User Created"},
        {"user", ujson(u)}
    });
}

void h_update_user(const Rest::Request& req, Http::ResponseWriter resp){
    auto t = get_auth(req);
    if(!t.valid){
        send(resp, 401, {
            {"error", "Not Authenticated"}
        });
        return;
    }
    if(t.role != "admin"){
        send(resp, 403, {
            {"error", "Admins only"}
        });
        return;
    }
    auto uid = req.param(":id").as<std::string>();
    json b;
    try{
        b = json::parse(req.body());
    }
    catch(...){
        send(resp, 400, {
            {"error", "bad JSON"}
        });
        return;
    }
    std::lock_guard<std::mutex> lk(mtx);
    auto* u = find_user_id(uid);
    if(!u){
        send(resp, 404, {
            {"error", "User Not Found"}
        });
        return;
    }
    if(b.contains("role")){
        std::string s = b["role"];
        if(s == "admin" || s == "analyst" || s == "viewer"){
            u->role = s;
        }
    }
    if(b.contains("status")){
        std::string s = b["status"];
        if(s == "active" || s == "inactive"){
            u->status = s;
        }
    }
    send(resp, 200, {
        {"message", "Updated"},
        {"user", ujson(*u)}
    });
}

void h_delete_user(const Rest::Request& req, Http::ResponseWriter resp){
    auto t = get_auth(req);
    if(!t.valid){
        send(resp, 401, {
            {"error", "Not Authenticated"}
        });
        return;
    }
    if(t.role != "admin"){
        send(resp, 403, {
            {"error", "Admins only"}
        });
        return;
    }
    auto uid = req.param(":id").as<std::string>();
    if(uid == t.id){
        send(resp, 400, {
            {"error", "Cannot Delete Yourself"}
        });
        return;
    }
    std::lock_guard<std::mutex> lk(mtx);
    auto it = std::remove_if(users.begin(), users.end(), [&](const User& u){
        return u.id == uid;
    });
    if(it == users.end()){
        send(resp, 404, {
            {"error", "User Not Found"}
        });
        return;
    }
    users.erase(it, users.end());
    send(resp, 200, {
        {"message", "Deleted"}
    });
}

void h_list_records(const Rest::Request& req, Http::ResponseWriter resp){
    auto t = get_auth(req);
    if(!t.valid){
        send(resp, 401, {
            {"error", "Not Authenticated"}
        });
        return;
    }

    auto qtype = req.query().get("type"), qcat = req.query().get("category"), qfrom = req.query().get("from"), qto = req.query().get("to"), qpage = req.query().get("page"), qlim = req.query().get("limit");
    
    int page = qpage.has_value()?std::stoi(qpage.value()):1;
    int lim = qlim.has_value()?std::min(std::stoi(qlim.value()), 100):20;
    if(page < 1){
        page = 1;
    }
    std::lock_guard<std::mutex> lk(mtx);
    std::vector<const Record*> v;
    for(auto& r : records){
        if(r.deleted){
            continue;
        }
        if(qtype.has_value() && r.type != qtype.value()){
            continue;
        }
        if(qcat.has_value() && r.category != qcat.value()){
            continue;
        }
        if(qfrom.has_value() && r.date < qfrom.value()){
            continue;
        }
        if(qto.has_value() && r.date > qto.value()){
            continue;
        }
        v.push_back(&r);
    }
    std::sort(v.begin(), v.end(), [](const Record* r1, const Record* r2){
        return (r1->date) > (r2->date);
    });
    int total = (int)v.size(), off = (page - 1) * lim;
    json arr = json::array();
    for(int i = off; i < std::min(off + lim, total); i++){
        arr.push_back(rjson(*v[i]));
    }
    send(resp, 200, {
        {"records", arr},
        {"pagination", {
            {"page", page},
            {"limit", lim},
            {"total", total}
        }}
    });
}

void h_get_record(const Rest::Request& req, Http::ResponseWriter resp){
    auto t = get_auth(req);
    if(!t.valid){
        send(resp, 401, {
            {"error", "Not Authenticated"}
        });
        return;
    }
    auto rid = req.param(":id").as<std::string>();
    std::lock_guard<std::mutex> lk(mtx);
    auto* r = find_rec(rid);
    if(!r){
        send(resp, 404, {
            {"error", "Record Not Found"}
        });
        return;
    }
    send(resp, 200, rjson(*r));
}

void h_create_record(const Rest::Request& req, Http::ResponseWriter resp){
    auto t = get_auth(req);
    if(!t.valid){
        send(resp, 401, {
            {"error", "Not Authenticated"}
        });
        return;
    }
    if(rlvl(t.role) < 2){
        send(resp, 403, {
            {"error", "Admin or Analyst Required"}
        });
        return;
    }
    json b;
    try{
        b = json::parse(req.body());
    }
    catch(...){
        send(resp, 400, {
            {"error", "bad JSON"}
        });
        return;
    }
    if(!b.contains("amount") || !b.contains("type") || !b.contains("date")){
        send(resp, 400, {
            {"error", "Amount, Type and Date Required"}
        });
        return;
    }
    std::string type = b["type"];
    if(type != "income" && type != "expense"){
        send(resp, 400, {
            {"error", "Type must be Income or Expense"}
        });
        return;
    }
    double amount;
    try{
        amount = b["amount"].get<double>();
    }
    catch(...){
        send(resp, 400, {
            {"error", "bad Amount"}
        });
        return;
    }
    if(amount <= 0){
        send(resp, 400, {
            {"error", "amount must be positive"}
        });
        return;
    }
    std::lock_guard<std::mutex> lk(mtx);
    Record r;
    r.id = gen_uuid();
    r.amount = amount;
    r.type = type;
    r.category = b.value("category", "");
    r.date = b["date"].get<std::string>();
    r.notes = b.value("notes", "");
    r.created_by = t.id;
    r.created_at = r.updated_at = now_str();
    records.push_back(r);
    send(resp, 201, rjson(r));
}

void h_update_record(const Rest::Request& req, Http::ResponseWriter resp){
    auto t = get_auth(req);
    if(!t.valid){
        send(resp, 401, {
            {"error", "Not Authenticated"}
        });
        return;
    }
    if(rlvl(t.role) < 2){
        send(resp, 403, {
            {"error", "Admin or Analyst Required"}
        });
        return;
    }
    auto rid = req.param(":id").as<std::string>();
    json b;
    try{
        b = json::parse(req.body());
    }
    catch(...){
        send(resp, 400, {
            {"error", "bad JSON"}
        });
        return;
    }
    std::lock_guard<std::mutex> lk(mtx);
    auto* r = find_rec(rid);
    if(!r){
        send(resp, 404, {
            {"error", "Record Not Found"}
        });
        return;
    }
    if(b.contains("amount")){
        double a = b["amount"].get<double>();
        if(a <= 0){
            send(resp, 400, {
                {"error", "bad Amount"}
            });
            return;
        }
        r->amount = a;
    }
    if(b.contains("type")){
        std::string ty = b["type"];
        if(ty != "income" && ty != "expense"){
            send(resp, 400, {
                {"error", "bad Type"}
            });
            return;
        }
        r->type = ty;
    }
    if(b.contains("category")){
        r->category = b["category"];
    }
    if(b.contains("date")){
        r->date = b["date"];
    }
    if(b.contains("notes")){
        r->notes = b["notes"];
    }
    r->updated_at = now_str();
    send(resp, 200, rjson(*r));
}

void h_delete_record(const Rest::Request& req, Http::ResponseWriter resp){
    auto t = get_auth(req);
    if(!t.valid){
        send(resp, 401, {
            {"error", "Not Authenticated"}
        });
        return;
    }
    if(t.role != "admin"){
        send(resp, 403, {
            {"error", "Admins Only"}
        });
        return;
    }
    auto rid = req.param(":id").as<std::string>();
    std::lock_guard<std::mutex> lk(mtx);
    auto* r = find_rec(rid);
    if(!r){
        send(resp, 404, {
            {"error", "Record Not Found"}
        });
        return;
    }
    r->deleted = true;
    send(resp, 200, {
        {"message", "Soft-Deleted"}
    });
}

void h_dash_summary(const Rest::Request& req, Http::ResponseWriter resp){
    auto t = get_auth(req);
    if(!t.valid){
        send(resp, 401, {
            {"error", "Not Authenticated"}
        });
        return;
    }
    std::lock_guard<std::mutex> lk(mtx);
    double inc = 0, exp = 0;
    for(auto& r : records){
        if(r.deleted){
            continue;
        }
        if(r.type == "income"){
            inc += r.amount;
        }
        else{
            exp += r.amount;
        }
    }
    double net = inc - exp;
    send(resp, 200, {
        {"total_income", inc},
        {"total_expense", exp},
        {"net_balance", net},
        {"status", net >= 0 ? "surplus" : "deficit"}
    });
}

void h_dash_category(const Rest::Request& req, Http::ResponseWriter resp){
    auto t = get_auth(req);
    if(!t.valid){
        send(resp, 401, {
            {"error", "Not Authenticated"}
        });
        return;
    }
    std::lock_guard<std::mutex> lk(mtx);
    std::map<std::string, std::map<std::string, double>> g;
    std::map<std::string, int> cnt;
    for(auto& r : records){
        if(r.deleted){
            continue;
        }
        std::string cat = r.category.empty() ? "uncategorized" : r.category;
        g[cat][r.type] += r.amount;
        cnt[cat]++;
    }
    json res = json::object();
    for(auto& [cat, tp] : g){
        res[cat] = {
            {"income", tp.count("income") ? tp["income"] : 0.0}, 
            {"expense", tp.count("expense") ? tp["expense"] : 0.0}, 
            {"count", cnt[cat]}
        };
    }
    send(resp, 200, {
        {"categories", res}
    });
}

void h_dash_monthly(const Rest::Request& req, Http::ResponseWriter resp){
    auto t = get_auth(req);
    if(!t.valid){
        send(resp, 401, {
            {"error", "Not Authenticated"}
        });
        return;
    }
    std::lock_guard<std::mutex> lk(mtx);
    std::map<std::string, std::map<std::string, double>> months;
    for(auto& r : records){
        if(r.deleted || r.date.size() < 7){
            continue;
        }
        months[r.date.substr(0, 7)][r.type] += r.amount;
    }
    json res = json::object();
    for(auto& [m, tp] : months){
        double i = tp.count("income") ? tp["income"] : 0.0;
        double e = tp.count("expense") ? tp["expense"] : 0.0;
        res[m] = {
            {"income", i},
            {"expense", e},
            {"net", i-e}
        };
    }
    send(resp, 200, {
        {"trends", res}
    });
}

void h_dash_recent(const Rest::Request& req, Http::ResponseWriter resp){
    auto t = get_auth(req);
    if(!t.valid){
        send(resp, 401, {
            {"error", "Not Authenticated"}
        });
        return;
    }
    auto ql = req.query().get("limit");
    int lim = ql.has_value() ? std::min(std::stoi(ql.value()), 50) : 10;
    std::lock_guard<std::mutex> lk(mtx);
    std::vector<const Record*> active;
    for(auto& r : records){
        if(!r.deleted){
            active.push_back(&r);
        }
    } 
    std::sort(active.begin(), active.end(), [](const Record* a, const Record* b){
        return a->created_at > b->created_at;
    });
    json arr = json::array();
    for(int i = 0; i < std::min(lim, (int)active.size()); i++){
        arr.push_back(rjson(*active[i]));
    }
    send(resp, 200, {
        {"recent", arr}
    });
}

void h_dash_stats(const Rest::Request& req, Http::ResponseWriter resp){
    auto t = get_auth(req);
    if(!t.valid){
        send(resp, 401, {
            {"error", "Not Authenticated"}
        });
        return;
    }
    std::lock_guard<std::mutex> lk(mtx);
    int total = 0, ci = 0, ce = 0;
    double si = 0, se = 0;
    const Record* big = nullptr;
    std::set<std::string> cats;
    for(auto& r : records){
        if(r.deleted){
            continue;
        }
        total++;
        cats.insert(r.category);
        if(r.type == "income"){
            si += r.amount;
            ci++;
        }
        else{
            se += r.amount;
            ce++;
        }
        if(!big || r.amount > big->amount){
            big = &r;
        }
    }
    json j = {
        {"total_records", total},
        {"unique_categories", (int)cats.size()},
        {"avg_income_per_entry", ci ? si/ci : 0.0},
        {"average_expense_per_entry", ce ? se/ce : 0.0}
    };
    if(rlvl(t.role) >= 2 && big){
        j["largest_transaction"] = rjson(*big);
    }
    send(resp, 200, j);
}

void seed(){
    for(auto& [n, p, r] : std::vector<std::tuple<std::string, std::string, std::string>>{
        {"admin1", "admin123", "admin"},
        {"analyst1", "analyst123", "analyst"},
        {"viewer1", "viewer123", "viewer"}
    }){
        users.push_back({gen_uuid(), n, sha256_hex(p), r, "active", now_str()});
    }
    std::vector<std::string> cats = {"salary", "rent", "food", "utilities", "freelance", "transport"};
    std::vector<std::string> months = {"2025-01", "2025-02", "2025-03", "2025-04", "2025-05", "2025-06", "2025-07", "2025-08", "2025-09", "2025-10"};
    for(int i = 0; i < 20; i++){
        Record r;
        r.id = gen_uuid();
        r.amount = 150.0 + i * 213.7;
        r.type = (i % 2 == 0) ? "income" : "expense";
        r.category = cats[i % cats.size()];
        r.date = months[i/2] + "-" + (((i % 28) + 1) < 10 ? "0" : "") + std::to_string((i % 28) + 1);
        r.notes = "Seeded #" + std::to_string(i + 1);
        r.created_by = "admin";
        r.created_at = r.updated_at = now_str();
        records.push_back(r);
    }
    std::cout << "[seed] " << users.size() << " users, " << records.size() << " records" << std::endl;
}

int main(){
    seed();
    Address addr(Ipv4::any(), Port(3000));
    Http::Endpoint server(addr);
    server.init(Http::Endpoint::options().threads(2).maxRequestSize(65536));
    Router router;
    Routes::Get(router,"/health", Routes::bind(&h_health));
    Routes::Post(router,"/auth/login", Routes::bind(&h_login));
    Routes::Get(router,"/users/me", Routes::bind(&h_me));
    Routes::Get(router,"/users", Routes::bind(&h_list_users));
    Routes::Post(router,"/users",Routes::bind(&h_create_user));
    Routes::Patch(router,"/users/:id", Routes::bind(&h_update_user));
    Routes::Delete(router,"/users/:id", Routes::bind(&h_delete_user));
    Routes::Get(router,"/records",  Routes::bind(&h_list_records));
    Routes::Get(router,"/records/:id",  Routes::bind(&h_get_record));
    Routes::Post(router,"/records",  Routes::bind(&h_create_record));
    Routes::Put(router,"/records/:id", Routes::bind(&h_update_record));
    Routes::Delete(router,"/records/:id", Routes::bind(&h_delete_record));
    Routes::Get(router,"/dashboard/summary", Routes::bind(&h_dash_summary));
    Routes::Get(router,"/dashboard/by-category", Routes::bind(&h_dash_category));
    Routes::Get(router,"/dashboard/monthly-trends", Routes::bind(&h_dash_monthly));
    Routes::Get(router,"/dashboard/recent", Routes::bind(&h_dash_recent));
    Routes::Get(router,"/dashboard/stats", Routes::bind(&h_dash_stats));
    server.setHandler(router.handler());
    std::cout << "Finance C++ backend on port 3000" << std::endl;
    std::cout << "Creds: admin/admin123  analyst1/analyst123  viewer1/viewer123" << std::endl;
    server.serve();
    return 0;
}
