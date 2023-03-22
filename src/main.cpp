#include "include/yao.h"
#include "rsa.h"

#include <chrono>
#include <future>

uint32_t* expand(char* input, size_t size)
{
    uint32_t* output = new uint32_t[size];
    for (size_t i = 0; i < size; i++)
    {
        output[i] = input[i];
    }

    return output;
} 

char* shrink(uint32_t* input, size_t size)
{
    char* output = new char[size];
    for (size_t i = 0; i < size; i++)
    {
        output[i] = (char) input[i];
    }

    return output;
}

std::string get_answer()
{    
    std::string answer;
    std::cin >> answer;
    return answer;
}

std::string non_block_stdin()
{
    std::chrono::milliseconds timeout(5);
    std::string answer = ""; //default to maybe
    std::future<std::string> future = std::async(get_answer);
    if (future.wait_for(timeout) == std::future_status::ready) answer = future.get();
    return answer;
}

std::string serial_read();
void serial_send(void* data, size_t size);

std::string non_block_serial()
{
    std::chrono::milliseconds timeout(5);
    std::string answer = ""; //default to maybe
    std::future<std::string> future = std::async(serial_read);
    if (future.wait_for(timeout) == std::future_status::ready) answer = future.get();
    return answer;
}

std::string rsa_to_string(const rsa_handler& rsa)
{
    return rsa.n.toString();
}

void set_rsa(rsa_handler& rsa, const std::string& input)
{
    rsa.n = InfInt(input);
}

ykey_t string_to_ykey_t(const std::string& input)
{
    std::string low = input.substr(0, 20);
    std::string high = input.substr(20, input.size());

    ykey_t out;
    out.lval = std::stoull(low);
    out.hval = std::stoull(high);
    return out;
}

std::string ykey_to_string(ykey_t input)
{
    std::string out = std::to_string(input.lval);
    out.resize(20);
    out.append(std::to_string(input.hval));
    return out;
}

class ShellInterface
{
private: 
    rsa_handler handler;
    YaoCipher yao;

public:
    ShellInterface()
    {
        handler = rsa_handler(100);
        handler.generate_keys();
        yao = YaoCipher();
    }

    void start()
    {
        while (true)
        {
            std::string str = non_block_stdin();
            if (str.size() != 0) 
            {
                // Send handler data
                std::string rsa_handler_str = rsa_to_string(handler);
                serial_send(rsa_handler_str.data(), rsa_handler_str.size());
                std::chrono::milliseconds timeout(1000);
                std::string answer = ""; //default to maybe
                std::future<std::string> future = std::async(serial_read);
                if (future.wait_for(timeout) == std::future_status::ready) answer = future.get();
                if (answer.size() != 0) 
                {
                    yao.set_key(string_to_ykey_t(answer));
                    if (str.size() % 16 != 0) 
                    {
                        str.resize(str.size() + 16 - str.size() % 16);
                    }

                    uint32_t* send = expand(str.data(), str.size());
                    yao.encrypt(send, str.size());
                    serial_send(send, str.size() * 4);
                    delete send;
                    break;
                }
            }

            str = non_block_serial();
            if (str.size() != 0)
            {
                set_rsa(handler, str);
                std::string send = handler.encrypt(InfInt(ykey_to_string(yao.get_key()))).toString();
                serial_send(send.data(), send.size());
                std::chrono::milliseconds timeout(1000);
                std::string answer = ""; //default to maybe
                std::future<std::string> future = std::async(serial_read);
                if (future.wait_for(timeout) == std::future_status::ready) answer = future.get();
                
                if (answer.size() != 0) 
                {
                    yao.decrypt((uint32_t*) answer.data(), answer.size() / 4);
                    std::string str_out(std::move(shrink((uint32_t*) answer.data(), answer.size() / 4)));
                    std::cout << str_out << std::endl;
                    break;
                }
            }
        }

        while (true)
        {
            // Main send recieve loop
            std::string str = non_block_stdin();
            if (str.size() != 0)
            {
                if (str.size() % 16 != 0) 
                {
                    str.resize(str.size() + 16 - str.size() % 16);
                }
            
                uint32_t* send = expand(str.data(), str.size());
                yao.encrypt(send, str.size());
                serial_send(send, str.size() * 4);
                delete send;
            }

            str = non_block_serial();
            if (str.size() != 0)
            {
                yao.decrypt((uint32_t*) str.data(), str.size() / 4);
                std::string str_out(std::move(shrink((uint32_t*) str.data(), str.size() / 4)));
                std::cout << str_out << std::endl;
            }
        }
    }
};

int main(void)
{
    // creates a public key using rsa
    // if something is sent to stdio (user input)
    // send the public key out
    // if a public key is recieved then create a yao_key and sent it
    // If you sent the public key then use the yao_key to encrypt received data (from shell) and send it to the other computer which will print it to stdio
    // Then both computers go into a loop where they are sending and reciving data
    /*
   
     */
}

