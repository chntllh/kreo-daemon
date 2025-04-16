#include <atomic>
#include <chrono>
#include <csignal>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <libusb-1.0/libusb.h>
#include <linux/uinput.h>
#include <map>
#include <mutex>
#include <stdexcept>
#include <thread>
#include <unistd.h>

#define VENDOR_ID 0x248a
#define PRODUCT_ID 0xfa02
#define ENDPOINT_IN 0x84
#define INTERFACE_NUMBER 0
#define PACKET_SIZE 64

std::atomic<bool> keep_running(true);
int uinput_fd;

void signal_handler(int signum)
{
    (void)signum;
    keep_running = false;
}

class LibUSBContext
{
public:
    LibUSBContext()
    {
        if (libusb_init(&ctx) != 0)
            throw std::runtime_error("Failed to initialize libusb");
    }

    ~LibUSBContext()
    {
        if (ctx)
            libusb_exit(ctx);
    }

    libusb_context *get()
    {
        return ctx;
    }

private:
    libusb_context *ctx = nullptr;
};

class USBDevice
{
public:
    USBDevice(libusb_context *ctx, uint16_t vendor, uint16_t product)
    {
        handle = libusb_open_device_with_vid_pid(ctx, vendor, product);
        if (!handle)
            throw std::runtime_error("Device not found");

        if (libusb_kernel_driver_active(handle, INTERFACE_NUMBER))
        {
            if (libusb_detach_kernel_driver(handle, INTERFACE_NUMBER) == 0)
                detached_kernel = true;
        }

        if (libusb_claim_interface(handle, INTERFACE_NUMBER) != 0)
        {
            libusb_close(handle);
            throw std::runtime_error("Failed to claim interface");
        }
    }

    ~USBDevice()
    {
        if (handle)
        {
            libusb_release_interface(handle, INTERFACE_NUMBER);
            if (detached_kernel)
            {
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
                int result = libusb_attach_kernel_driver(handle, INTERFACE_NUMBER);
                if (result != 0)
                    std::cerr << "Failed to reattach kernel driver, error code: "
                              << result << std::endl;
                else
                    std::cout << "Kernel driver successfully reattached" << std::endl;
            }
            libusb_close(handle);
        }
    }

    libusb_device_handle *get()
    {
        return handle;
    }

private:
    libusb_device_handle *handle = nullptr;
    bool detached_kernel = false;
};

int setup_uinput_device()
{
    int fd = open("/dev/uinput", O_WRONLY | O_NONBLOCK);
    if (fd < 0)
        throw std::runtime_error("Failed to open /dev/uinput");

    ioctl(fd, UI_SET_EVBIT, EV_KEY);
    ioctl(fd, UI_SET_KEYBIT, BTN_LEFT);
    ioctl(fd, UI_SET_KEYBIT, BTN_RIGHT);
    ioctl(fd, UI_SET_KEYBIT, BTN_MIDDLE);
    ioctl(fd, UI_SET_KEYBIT, BTN_SIDE);
    ioctl(fd, UI_SET_KEYBIT, BTN_EXTRA);

    ioctl(fd, UI_SET_EVBIT, EV_REL);
    ioctl(fd, UI_SET_RELBIT, REL_X);
    ioctl(fd, UI_SET_RELBIT, REL_Y);
    ioctl(fd, UI_SET_RELBIT, REL_WHEEL);

    struct uinput_user_dev uidev = {};
    snprintf(uidev.name, UINPUT_MAX_NAME_SIZE, "kreo-mouse-virtual");
    uidev.id.bustype = BUS_USB;
    uidev.id.vendor = 0x1234;
    uidev.id.product = 0x5678;
    uidev.id.version = 1;

    write(fd, &uidev, sizeof(uidev));

    if (ioctl(fd, UI_DEV_CREATE) < 0)
    {
        close(fd);
        throw std::runtime_error("UI_DEV_CREATE failed");
    }

    return fd;
}

void emit(int fd, uint16_t type, uint16_t code, int32_t value)
{
    struct input_event ev = {};
    gettimeofday(&ev.time, nullptr);
    ev.type = type;
    ev.code = code;
    ev.value = value;
    write(fd, &ev, sizeof(ev));
}

void transfer_callback(struct libusb_transfer *transfer)
{
    if (transfer->status == LIBUSB_TRANSFER_COMPLETED && transfer->actual_length > 0)
    {
        unsigned char *data = transfer->buffer;
        int uinput_fd = *static_cast<int *>(transfer->user_data);

        if (data[0] != 0x01)
        {
            std::cout << "Packet: ";
            for (int i = 0; i < transfer->actual_length; i++)
                printf("%02x ", data[i]);
            std::cout << std::endl;

            libusb_submit_transfer(transfer);
            return;
        }

        // std::cout << "Packet: ";
        // for (int i = 0; i < transfer->actual_length; i++)
        //     printf("%02x ", data[i]);
        // std::cout << std::endl;

        uint8_t bitmask = data[1];

        int16_t dx = static_cast<int16_t>(data[2] | (data[3] << 8));
        int16_t dy = static_cast<int16_t>(data[4] | (data[5] << 8));

        int8_t scroll = static_cast<int8_t>(data[6]);

        if (scroll != 0)
        {
            emit(uinput_fd, EV_REL, REL_WHEEL, scroll);
            emit(uinput_fd, EV_SYN, SYN_REPORT, 0);
        }
        if (dx != 0)
            emit(uinput_fd, EV_REL, REL_X, dx);
        if (dy != 0)
            emit(uinput_fd, EV_REL, REL_Y, dy);
        if (dx != 0 || dy != 0)
            emit(uinput_fd, EV_SYN, SYN_REPORT, 0);

        static std::map<uint8_t, uint16_t> bit_to_btn = {
            {0x01, BTN_LEFT},
            {0x02, BTN_RIGHT},
            {0x04, BTN_MIDDLE},
            {0x08, BTN_SIDE},
            {0x10, BTN_EXTRA},
        };

        static std::map<uint16_t, bool> button_states = {
            {BTN_LEFT, false},
            {BTN_RIGHT, false},
            {BTN_MIDDLE, false},
            {BTN_SIDE, false},
            {BTN_EXTRA, false},
        };

        static std::mutex button_mutex;

        std::lock_guard<std::mutex> lock(button_mutex);

        for (const auto &[bit, btn] : bit_to_btn)
        {
            bool is_pressed = bitmask & bit;

            if (is_pressed && !button_states[btn])
            {
                emit(uinput_fd, EV_KEY, btn, 1);
                emit(uinput_fd, EV_SYN, SYN_REPORT, 0);
                button_states[btn] = true;
            }
            else if (!is_pressed && button_states[btn])
            {
                emit(uinput_fd, EV_KEY, btn, 0);
                emit(uinput_fd, EV_SYN, SYN_REPORT, 0);
                button_states[btn] = false;
            }
        }
    }

    if (keep_running)
        libusb_submit_transfer(transfer);
}

int main()
{
    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);

    try
    {
        LibUSBContext libusb;
        USBDevice mouse(libusb.get(), VENDOR_ID, PRODUCT_ID);
        uinput_fd = setup_uinput_device();

        libusb_transfer *transfer = libusb_alloc_transfer(0);
        // unsigned char *buffer = new unsigned char[PACKET_SIZE];
        std::unique_ptr<unsigned char[]> buffer(new unsigned char[PACKET_SIZE]);

        // int *fd_ptr = new int(uinput_fd);
        std::unique_ptr<int> fd_ptr(new int(uinput_fd));

        libusb_fill_interrupt_transfer(transfer, mouse.get(), ENDPOINT_IN, buffer.get(), PACKET_SIZE, transfer_callback, fd_ptr.get(), 0);

        if (libusb_submit_transfer(transfer) != 0)
        {
            libusb_free_transfer(transfer);
            throw std::runtime_error("Failed to submit transfer");
            keep_running = false;
        }

        std::cout << "Async listener started..." << std::endl;

        while (keep_running)
        {
            libusb_handle_events(libusb.get());
        }

        std::cout << "Cleaning up..." << std::endl;

        if (transfer)
        {
            libusb_cancel_transfer(transfer);

            timeval tv;
            tv.tv_sec = 0;
            tv.tv_usec = 1000;

            for (int i = 0; i < 100; i++)
            {
                int r = libusb_handle_events_timeout(libusb.get(), &tv);
                if (r < 0)
                    break;

                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }

            libusb_free_transfer(transfer);
            // delete[] buffer.get();
            // delete fd_ptr.get();
        }

        if (uinput_fd >= 0)
        {
            ioctl(uinput_fd, UI_DEV_DESTROY);
            close(uinput_fd);
        }
    }
    catch (const std::exception &e)
    {
        std::cerr << "Fatal: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}