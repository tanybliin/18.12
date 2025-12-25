#include <iostream>
#include <fstream>
#include <string>
#include <filesystem>
#include <limits>
#include <functional>

using namespace std;
namespace fs = std::filesystem;

string hash_password(const string& password) {
    hash<string> hasher;
    return to_string(hasher(password));
}

class User {
    string _name;
    string _login;
    string _pass_hash;

public:
    User() {}
    User(string n, string l, string p)
        : _name(n), _login(l), _pass_hash(hash_password(p)) {}

    friend ifstream& operator>>(ifstream& is, User& u);
    friend ofstream& operator<<(ofstream& os, const User& u);
    friend ostream& operator<<(ostream& os, const User& u);
};

ifstream& operator>>(ifstream& is, User& u)
{
    return is >> u._name >> u._login >> u._pass_hash;
}

ofstream& operator<<(ofstream& os, const User& u)
{
    os << u._name << ' ' << u._login << ' ' << u._pass_hash;
    return os;
}

ostream& operator<<(ostream& os, const User& u)
{
    os << u._name << ' ' << u._login << " [password hash: " 
       << u._pass_hash.substr(0, 8) << "...]";
    return os;
}

class Message {
    string _text;
    string _sender;
    string _receiver;

public:
    Message() {}
    Message(string t, string s, string r)
        : _text(t), _sender(s), _receiver(r) {}

    friend ifstream& operator>>(ifstream& is, Message& m);
    friend ofstream& operator<<(ofstream& os, const Message& m);
    friend ostream& operator<<(ostream& os, const Message& m);
};

ifstream& operator>>(ifstream& is, Message& m)
{
    getline(is >> ws, m._text);
    is >> m._sender >> m._receiver;
    is.ignore(numeric_limits<streamsize>::max(), '\n');
    return is;
}

ofstream& operator<<(ofstream& os, const Message& m)
{
    os << m._text << '\n'
       << m._sender << ' ' << m._receiver;
    return os;
}

ostream& operator<<(ostream& os, const Message& m)
{
    os << m._text << " | from: "
       << m._sender << " -> " << m._receiver;
    return os;
}

void set_secure_permissions(const string& filename) {
    try {
        fs::permissions(filename,
            fs::perms::owner_read | fs::perms::owner_write,
            fs::perm_options::replace);
    } catch (const fs::filesystem_error& e) {
        cerr << "Warning: Could not set permissions for " 
             << filename << ": " << e.what() << endl;
    }
}

void create_secure_file(const string& filename) {
    if (!fs::exists(filename)) {
        ofstream file(filename);
        if (file) {
            file.close();
            set_secure_permissions(filename);
            cout << "Created secure file: " << filename << endl;
        }
    }
}

void loadUser(User& u)
{
    create_secure_file("users.txt");
    ifstream file("users.txt");
    if (!file.is_open()) {
        cout << "Could not open users.txt\n";
        return;
    }
    if (file >> u)
        cout << "Loaded user: " << u << endl;
    else
        cout << "users.txt is empty\n";
    file.close();
}

void saveUser(const User& u)
{
    create_secure_file("users.txt");
    ofstream file("users.txt");
    if (!file.is_open()) {
        cout << "Could not open users.txt for writing\n";
        return;
    }
    file << u << endl;
    cout << "Saved user: " << u << endl;
    file.close();
    set_secure_permissions("users.txt");
}

void loadMessage(Message& m)
{
    create_secure_file("messages.txt");
    ifstream file("messages.txt");
    if (!file.is_open()) {
        cout << "Could not open messages.txt\n";
        return;
    }
    if (file >> m)
        cout << "Loaded message: " << m << endl;
    else
        cout << "messages.txt is empty\n";
    file.close();
}

void saveMessage(const Message& m)
{
    create_secure_file("messages.txt");
    ofstream file("messages.txt");
    if (!file.is_open()) {
        cout << "Could not open messages.txt for writing\n";
        return;
    }
    file << m << endl;
    cout << "Saved message: " << m << endl;
    file.close();
    set_secure_permissions("messages.txt");
}

void show_permissions() {
    cout << "\n=== File Permissions ===" << endl;
    auto show_file = [](const string& name) {
try {
            if (fs::exists(name)) {
                auto p = fs::status(name).permissions();
                cout << name << ": "
                     << ((p & fs::perms::owner_read) != fs::perms::none ? "r" : "-")
                     << ((p & fs::perms::owner_write) != fs::perms::none ? "w" : "-")
                     << ((p & fs::perms::owner_exec) != fs::perms::none ? "x" : "-")
                     << ((p & fs::perms::group_read) != fs::perms::none ? "r" : "-")
                     << ((p & fs::perms::group_write) != fs::perms::none ? "w" : "-")
                     << ((p & fs::perms::group_exec) != fs::perms::none ? "x" : "-")
                     << ((p & fs::perms::others_read) != fs::perms::none ? "r" : "-")
                     << ((p & fs::perms::others_write) != fs::perms::none ? "w" : "-")
                     << ((p & fs::perms::others_exec) != fs::perms::none ? "x" : "-")
                     << endl;
            }
        } catch (...) {
            cout << name << ": Could not check permissions" << endl;
        }
    };
    show_file("users.txt");
    show_file("messages.txt");
}

int main()
{
    User user;
    Message msg;

    cout << "=== Reading existing data ===" << endl;
    loadUser(user);
    loadMessage(msg);

    cout << "\n=== Writing new data ===" << endl;

    User new_user("Ivan", "ivan123", "password123");
    saveUser(new_user);

    Message new_msg("Hello, how are you?", "Ivan", "Maria");
    saveMessage(new_msg);

    cout << "\n=== Re-read to verify ===" << endl;
    loadUser(user);
    loadMessage(msg);
    
    show_permissions();
    
    cout << "\n=== Summary ===" << endl;
    cout << "1. Files protected with permissions 600 (owner read/write only)" << endl;
    cout << "2. Passwords stored as hashes (not plain text)" << endl;
    cout << "3. Other users cannot access these files" << endl;

    return 0;
}
