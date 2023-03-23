#include "include/yao.h"
#include "rsa.h"

#include <chrono>
#include <future>

// C library headers
#include <stdio.h>
#include <string.h>

// Linux headers
#include <fcntl.h> // Contains file controls like O_RDWR
#include <errno.h> // Error integer and strerror() function
#include <termios.h> // Contains POSIX terminal control definitions
#include <unistd.h> // write(), read(), close()

int serial_port = 0;
struct termios tty;

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

std::string serial_read()
{
    // char read_buf [256];

    // int num_bytes = read(, &read_buf, sizeof(read_buf));

    // // n is the number of bytes read. n may be 0 if no bytes were received, and can also be -1 to signal an error.
    // if (num_bytes < 0) {
    //     printf("Error reading: %s", strerror(errno));
    //     return std::string();
    // } else if (num_bytes == 0) {
    //     return std::string();
    // } else {
    //     return std::string(read_buf);
    // }


}
void serial_send(void* data, size_t size);

std::string non_block_serial()
{
    // std::chrono::milliseconds timeout(5);
    // std::string answer = ""; //default to maybe
    // std::future<std::string> future = std::async(serial_read);
    // if (future.wait_for(timeout) == std::future_status::ready) answer = future.get();
    // return answer;
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

int main(int argc, char** argv)
{
    // creates a public key using rsa
    // if something is sent to stdio (user input)
    // send the public key out
    // if a public key is recieved then create a yao_key and sent it
    // If you sent the public key then use the yao_key to encrypt received data (from shell) and send it to the other computer which will print it to stdio
    // Then both computers go into a loop where they are sending and reciving data
    /*
   
     */

    serial_port = open(argv[1], O_RDWR);
    // struct termios tty;

    if(tcgetattr(serial_port, &tty) != 0) {
        printf("Error %i from tcgetattr: %s\n", errno, strerror(errno));
        return 1;
    }

    tty.c_cflag &= ~PARENB; // Clear parity bit, disabling parity (most common)
    tty.c_cflag &= ~CSTOPB; // Clear stop field, only one stop bit used in communication (most common)
    tty.c_cflag &= ~CSIZE; // Clear all bits that set the data size 
    tty.c_cflag |= CS8; // 8 bits per byte (most common)
    tty.c_cflag &= ~CRTSCTS; // Disable RTS/CTS hardware flow control (most common)
    tty.c_cflag |= CREAD | CLOCAL; // Turn on READ & ignore ctrl lines (CLOCAL = 1)

    tty.c_lflag &= ~ICANON;
    tty.c_lflag &= ~ECHO; // Disable echo
    tty.c_lflag &= ~ECHOE; // Disable erasure
    tty.c_lflag &= ~ECHONL; // Disable new-line echo
    tty.c_lflag &= ~ISIG; // Disable interpretation of INTR, QUIT and SUSP
    tty.c_iflag &= ~(IXON | IXOFF | IXANY); // Turn off s/w flow ctrl
    tty.c_iflag &= ~(IGNBRK|BRKINT|PARMRK|ISTRIP|INLCR|IGNCR|ICRNL); // Disable any special handling of received bytes

    tty.c_oflag &= ~OPOST; // Prevent special interpretation of output bytes (e.g. newline chars)
    tty.c_oflag &= ~ONLCR; // Prevent conversion of newline to carriage return/line feed
    // tty.c_oflag &= ~OXTABS; // Prevent conversion of tabs to spaces (NOT PRESENT ON LINUX)
    // tty.c_oflag &= ~ONOEOT; // Prevent removal of C-d chars (0x004) in output (NOT PRESENT ON LINUX)

    tty.c_cc[VTIME] = 10;    // Wait for up to 1s (10 deciseconds), returning as soon as any data is received.
    tty.c_cc[VMIN] = 0;

    // Set in/out baud rate to be 9600
    cfsetispeed(&tty, B115200);
    cfsetospeed(&tty, B115200);

    if (serial_port < 0) {
        printf("Error %i from open: %s\n", errno, strerror(errno));
    }

    unsigned char msg[] = { 'H', 'e', 'l', 'l', 'o', '\r' };
    write(serial_port, msg, sizeof(msg));

    // Allocate memory for read buffer, set size according to your needs
    char read_buf [256];

    // Normally you wouldn't do this memset() call, but since we will just receive
    // ASCII data for this example, we'll set everything to 0 so we can
    // call printf() easily.
    memset(&read_buf, '\0', sizeof(read_buf));

    // Read bytes. The behaviour of read() (e.g. does it block?,
    // how long does it block for?) depends on the configuration
    // settings above, specifically VMIN and VTIME

    int num_bytes;

    // while (1) {
    //     num_bytes = read(serial_port, &read_buf, sizeof(read_buf));

    //     // n is the number of bytes read. n may be 0 if no bytes were received, and can also be -1 to signal an error.
    //     if (num_bytes < 0) {
    //         printf("Error reading: %s", strerror(errno));
    //         return 1;
    //     } else if (num_bytes == 0) {
    //         continue;
    //     } else {
    //         printf("Read %i bytes. Received message: %s", num_bytes, read_buf);
    //     }
    // }

    write(serial_port, msg, sizeof(msg));

    // Here we assume we received ASCII data, but you might be sending raw bytes (in that case, don't try and
    // print it to the screen like this!)
    printf("Read %i bytes. Received message: %s", num_bytes, read_buf);

    close(serial_port);
    return 0; // success
}

