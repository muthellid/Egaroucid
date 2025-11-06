/* @file common_b3.hpp */

#pragma once
#include <iostream>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <time.h>
#include <chrono>
#include <random>
#include <string>
#include "setting.hpp"

// board size definition
constexpr int HW_B3 = 8;
constexpr int HW_M1_B3 = 7;
constexpr int HW_P1_B3 = 9;
constexpr int HW2_B3 = 64;
constexpr int HW2_M1_B3 = 63;
constexpr int HW2_P1_B3 = 65;
constexpr int N_INVALID_B3 = 12;
constexpr int N_ACTIVE_SQUARES_B3 = HW2_B3 - N_INVALID_B3; // 52

// color definition
constexpr int BLACK_B3 = 0;
constexpr int WHITE_B3 = 1;
constexpr int VACANT_B3 = 2;

// constant
constexpr int N_8BIT_B3 = 256; // 2 ^ 8
constexpr int N_16BIT_B3 = 65536; // 2 ^ 16
constexpr int INF_B3 = 100000000;
constexpr int SCORE_INF_B3 = 127;
constexpr int SCORE_MAX_B3 = 52;

// undefined legal bitboard: set bit on d4, d5, e4, and e5
constexpr uint64_t LEGAL_UNDEFINED_B3 = 0x0000001818000000ULL;

// invalid mask for Board3
constexpr uint64_t INVALID_MASK_B3 = 0xC3810000000081C3ULL;

// cell type masks
constexpr int N_CELL_TYPE_B3 = 10;
constexpr uint64_t cell_type_mask_b3[N_CELL_TYPE_B3] = {
    0x2400810000810024ULL & ~INVALID_MASK_B3, // corner
    0x4281000000008142ULL & ~INVALID_MASK_B3, // C
    0x2400810000810024ULL & ~INVALID_MASK_B3, // A
    0x1800008181000018ULL & ~INVALID_MASK_B3, // B
    0x0042000000004200ULL & ~INVALID_MASK_B3, // X
    0x0024420000422400ULL & ~INVALID_MASK_B3, // a
    0x0018004242001800ULL & ~INVALID_MASK_B3, // b
    0x0000240000240000ULL & ~INVALID_MASK_B3, // box corner
    0x0000182424180000ULL & ~INVALID_MASK_B3, // box edge
    0x0000001818000000ULL                    // center (unchanged)
};

// cell type map
constexpr int cell_type_b3[HW2_B3] = {
    -1, -1, 2, 3, 3, 2, -1, -1,
    -1, 4, 5, 6, 6, 5, 4, -1,
     2, 5, 7, 8, 8, 7, 5, 2,
     3, 6, 8, 9, 9, 8, 6, 3,
     3, 6, 8, 9, 9, 8, 6, 3,
     2, 5, 7, 8, 8, 7, 5, 2,
    -1, 4, 5, 6, 6, 5, 4, -1,
    -1, -1, 2, 3, 3, 2, -1, -1
};
/*
    @brief bits around the cell are set (Board3)
*/
constexpr uint64_t bit_around_b3[HW2_B3] = {
    0x0000000000000302ULL & ~INVALID_MASK_B3, 0x0000000000000604ULL & ~INVALID_MASK_B3, 0x0000000000000e0aULL & ~INVALID_MASK_B3, 0x0000000000001c14ULL & ~INVALID_MASK_B3,
    0x0000000000003828ULL & ~INVALID_MASK_B3, 0x0000000000007050ULL & ~INVALID_MASK_B3, 0x0000000000006020ULL & ~INVALID_MASK_B3, 0x000000000000c040ULL & ~INVALID_MASK_B3,
    0x0000000000030200ULL & ~INVALID_MASK_B3, 0x0000000000060400ULL & ~INVALID_MASK_B3, 0x00000000000e0a00ULL & ~INVALID_MASK_B3, 0x00000000001c1400ULL & ~INVALID_MASK_B3,
    0x0000000000382800ULL & ~INVALID_MASK_B3, 0x0000000000705000ULL & ~INVALID_MASK_B3, 0x0000000000602000ULL & ~INVALID_MASK_B3, 0x0000000000c04000ULL & ~INVALID_MASK_B3,
    0x0000000003020300ULL & ~INVALID_MASK_B3, 0x0000000006040600ULL & ~INVALID_MASK_B3, 0x000000000e0a0e00ULL & ~INVALID_MASK_B3, 0x000000001c141c00ULL & ~INVALID_MASK_B3,
    0x0000000038283800ULL & ~INVALID_MASK_B3, 0x0000000070507000ULL & ~INVALID_MASK_B3, 0x0000000060206000ULL & ~INVALID_MASK_B3, 0x00000000c040c000ULL & ~INVALID_MASK_B3,
    0x0000000302030000ULL & ~INVALID_MASK_B3, 0x0000000604060000ULL & ~INVALID_MASK_B3, 0x0000000e0a0e0000ULL & ~INVALID_MASK_B3, 0x0000001c141c0000ULL & ~INVALID_MASK_B3,
    0x0000003828380000ULL & ~INVALID_MASK_B3, 0x0000007050700000ULL & ~INVALID_MASK_B3, 0x0000006020600000ULL & ~INVALID_MASK_B3, 0x000000c040c00000ULL & ~INVALID_MASK_B3,
    0x0000030203000000ULL & ~INVALID_MASK_B3, 0x0000060406000000ULL & ~INVALID_MASK_B3, 0x00000e0a0e000000ULL & ~INVALID_MASK_B3, 0x00001c141c000000ULL & ~INVALID_MASK_B3,
    0x0000382838000000ULL & ~INVALID_MASK_B3, 0x0000705070000000ULL & ~INVALID_MASK_B3, 0x0000602060000000ULL & ~INVALID_MASK_B3, 0x0000c040c0000000ULL & ~INVALID_MASK_B3,
    0x0003020300000000ULL & ~INVALID_MASK_B3, 0x0006040600000000ULL & ~INVALID_MASK_B3, 0x000e0a0e00000000ULL & ~INVALID_MASK_B3, 0x001c141c00000000ULL & ~INVALID_MASK_B3,
    0x0038283800000000ULL & ~INVALID_MASK_B3, 0x0070507000000000ULL & ~INVALID_MASK_B3, 0x0060206000000000ULL & ~INVALID_MASK_B3, 0x00c040c000000000ULL & ~INVALID_MASK_B3,
    0x0002030000000000ULL & ~INVALID_MASK_B3, 0x0004060000000000ULL & ~INVALID_MASK_B3, 0x000a0e0000000000ULL & ~INVALID_MASK_B3, 0x00141c0000000000ULL & ~INVALID_MASK_B3,
    0x0028380000000000ULL & ~INVALID_MASK_B3, 0x0050700000000000ULL & ~INVALID_MASK_B3, 0x0020600000000000ULL & ~INVALID_MASK_B3, 0x0040c00000000000ULL & ~INVALID_MASK_B3,
    0x0203000000000000ULL & ~INVALID_MASK_B3, 0x0406000000000000ULL & ~INVALID_MASK_B3, 0x0a0e000000000000ULL & ~INVALID_MASK_B3, 0x141c000000000000ULL & ~INVALID_MASK_B3,
    0x2838000000000000ULL & ~INVALID_MASK_B3, 0x5070000000000000ULL & ~INVALID_MASK_B3, 0x2060000000000000ULL & ~INVALID_MASK_B3, 0x40c0000000000000ULL & ~INVALID_MASK_B3
};
/*
    @brief bits radiating the cell are set (Board3)
*/
constexpr uint64_t bit_radiation_b3[HW2_B3] = {
    0x81412111090503FEULL & ~INVALID_MASK_B3, 0x02824222120A07FDULL & ~INVALID_MASK_B3, 0x0404844424150EFBULL & ~INVALID_MASK_B3, 0x08080888492A1CF7ULL & ~INVALID_MASK_B3,
    0x10101011925438EFULL & ~INVALID_MASK_B3, 0x2020212224A870DFULL & ~INVALID_MASK_B3, 0x404142444850E0BFULL & ~INVALID_MASK_B3, 0x8182848890A0C07FULL & ~INVALID_MASK_B3,
    0x412111090503FE03ULL & ~INVALID_MASK_B3, 0x824222120A07FD07ULL & ~INVALID_MASK_B3, 0x04844424150EFB0EULL & ~INVALID_MASK_B3, 0x080888492A1CF71CULL & ~INVALID_MASK_B3,
    0x101011925438EF38ULL & ~INVALID_MASK_B3, 0x20212224A870DF70ULL & ~INVALID_MASK_B3, 0x4142444850E0BFE0ULL & ~INVALID_MASK_B3, 0x82848890A0C07FC0ULL & ~INVALID_MASK_B3,
    0x2111090503FE0305ULL & ~INVALID_MASK_B3, 0x4222120A07FD070AULL & ~INVALID_MASK_B3, 0x844424150EFB0E15ULL & ~INVALID_MASK_B3, 0x0888492A1CF71C2AULL & ~INVALID_MASK_B3,
    0x1011925438EF3854ULL & ~INVALID_MASK_B3, 0x212224A870DF70A8ULL & ~INVALID_MASK_B3, 0x42444850E0BFE050ULL & ~INVALID_MASK_B3, 0x848890A0C07FC0A0ULL & ~INVALID_MASK_B3,
    0x11090503FE030509ULL & ~INVALID_MASK_B3, 0x22120A07FD070A12ULL & ~INVALID_MASK_B3, 0x4424150EFB0E1524ULL & ~INVALID_MASK_B3, 0x88492A1CF71C2A49ULL & ~INVALID_MASK_B3,
    0x11925438EF385492ULL & ~INVALID_MASK_B3, 0x2224A870DF70A824ULL & ~INVALID_MASK_B3, 0x444850E0BFE05048ULL & ~INVALID_MASK_B3, 0x8890A0C07FC0A090ULL & ~INVALID_MASK_B3,
    0x090503FE03050911ULL & ~INVALID_MASK_B3, 0x120A07FD070A1222ULL & ~INVALID_MASK_B3, 0x24150EFB0E152444ULL & ~INVALID_MASK_B3, 0x492A1CF71C2A4988ULL & ~INVALID_MASK_B3,
    0x925438EF38549211ULL & ~INVALID_MASK_B3, 0x24A870DF70A82422ULL & ~INVALID_MASK_B3, 0x4850E0BFE0504844ULL & ~INVALID_MASK_B3, 0x90A0C07FC0A09088ULL & ~INVALID_MASK_B3,
    0x0503FE0305091121ULL & ~INVALID_MASK_B3, 0x0A07FD070A122242ULL & ~INVALID_MASK_B3, 0x150EFB0E15244484ULL & ~INVALID_MASK_B3, 0x2A1CF71C2A498808ULL & ~INVALID_MASK_B3,
    0x5438EF3854921110ULL & ~INVALID_MASK_B3, 0xA870DF70A8242221ULL & ~INVALID_MASK_B3, 0x50E0BFE050484442ULL & ~INVALID_MASK_B3, 0xA0C07FC0A0908884ULL & ~INVALID_MASK_B3,
    0x03FE030509112141ULL & ~INVALID_MASK_B3, 0x07FD070A12224282ULL & ~INVALID_MASK_B3, 0x0EFB0E1524448404ULL & ~INVALID_MASK_B3, 0x1CF71C2A49880808ULL & ~INVALID_MASK_B3,
    0x38EF385492111010ULL & ~INVALID_MASK_B3, 0x70DF70A824222120ULL & ~INVALID_MASK_B3, 0xE0BFE05048444241ULL & ~INVALID_MASK_B3, 0xC07FC0A090888482ULL & ~INVALID_MASK_B3,
    0xFE03050911214181ULL & ~INVALID_MASK_B3, 0xFD070A1222428202ULL & ~INVALID_MASK_B3, 0xFB0E152444840404ULL & ~INVALID_MASK_B3, 0xF71C2A4988080808ULL & ~INVALID_MASK_B3,
    0xEF38549211101010ULL & ~INVALID_MASK_B3, 0xDF70A82422212020ULL & ~INVALID_MASK_B3, 0xBFE0504844424140ULL & ~INVALID_MASK_B3, 0x7FC0A09088848281ULL & ~INVALID_MASK_B3
};
// set false to stop all search immediately
bool global_searching_b3 = true;

/*
    @brief timing function

    @return time in milliseconds
*/
inline uint64_t tim_b3() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::high_resolution_clock::now().time_since_epoch()
    ).count();
}

std::mt19937 raw_myrandom_b3(tim_b3());

/*
    @brief random function

    @return random value from 0.0 to 1.0 (not including 1.0)
*/
inline double myrandom_b3() {
    return (double)raw_myrandom_b3() / std::mt19937::max();
}

/*
    @brief randrange function

    @param s                    minimum integer
    @param e                    maximum integer
    @return random integer from s to e - 1
*/
inline int32_t myrandrange_b3(int32_t s, int32_t e) {
    return s + (int)((e - s) * myrandom_b3());
}

/*
    @brief random integer function

    @return random 32bit integer
*/
inline uint32_t myrand_uint_b3() {
    return (uint32_t)raw_myrandom_b3();
}

/*
    @brief random integer function with bit reversed

    @return random 32bit integer with reversed bits
*/
inline uint32_t myrand_uint_rev_b3() {
    uint32_t x = raw_myrandom_b3();
    x = ((x & 0x55555555U) << 1) | ((x & 0xAAAAAAAAU) >> 1);
    x = ((x & 0x33333333U) << 2) | ((x & 0xCCCCCCCCU) >> 2);
    x = ((x & 0x0F0F0F0FU) << 4) | ((x & 0xF0F0F0F0U) >> 4);
    x = ((x & 0x00FF00FFU) << 8) | ((x & 0xFF00FF00U) >> 8);
    return ((x & 0x0000FFFFU) << 16) | ((x & 0xFFFF0000U) >> 16);
}

/*
    @brief random integer function

    @return random 64bit integer
*/
inline uint64_t myrand_ull_b3() {
    return ((uint64_t)raw_myrandom_b3() << 32) | (uint64_t)raw_myrandom_b3();
}

/*
    @brief open a file

    wrapper for cross platform

    @param fp                   FILE
    @param file                 file name
    @param mode                 open mode
    @return file opened?
*/
inline bool file_open_b3(FILE **fp, const char *file, const char *mode) {
#ifdef _WIN64
    return fopen_s(fp, file, mode) == 0;
#elif _WIN32
    return fopen_s(fp, file, mode) == 0;
#else
    *fp = fopen(file, mode);
    return *fp != NULL;
#endif
}

/*
    @brief calculate NPS (Nodes Per Second)

    @param n_nodes              number of nodes
    @param elapsed              time
    @return NPS
*/
inline uint64_t calc_nps_b3(uint64_t n_nodes, uint64_t elapsed) {
    if (elapsed == 0ULL) elapsed = 1ULL;
    return n_nodes * 1000ULL / elapsed;
}

int get_localtime_b3(tm* a, time_t* b) {
#if _WIN64 || _WIN32
    return localtime_s(a, b);
#else
    a = localtime(b);
    return 0;
#endif
}

inline std::string calc_date_b3() {
    time_t now;
    tm newtime;
    time(&now);
    get_localtime_b3(&newtime, &now);
    std::stringstream sout;
    std::string year = std::to_string(newtime.tm_year + 1900);
    sout << std::setfill('0') << std::setw(2) << newtime.tm_mon + 1;
    std::string month = sout.str(); sout.str(""); sout.clear();
    sout << std::setfill('0') << std::setw(2) << newtime.tm_mday;
    std::string day = sout.str(); sout.str(""); sout.clear();
    sout << std::setfill('0') << std::setw(2) << newtime.tm_hour;
    std::string hour = sout.str(); sout.str(""); sout.clear();
    sout << std::setfill('0') << std::setw(2) << newtime.tm_min;
    std::string minute = sout.str(); sout.str(""); sout.clear();
    sout << std::setfill('0') << std::setw(2) << newtime.tm_sec;
    std::string second = sout.str();
    return year + "_" + month + "_" + day + "_" + hour + "_" + minute + "_" + second;
}

inline void calc_date_b3(int *year, int *month, int *day, int *hour, int *minute, int *second) {
    time_t now;
    tm newtime;
    time(&now);
    get_localtime_b3(&newtime, &now);
    *year = newtime.tm_year + 1900;
    *month = newtime.tm_mon + 1;
    *day = newtime.tm_mday;
    *hour = newtime.tm_hour;
    *minute = newtime.tm_min;
    *second = newtime.tm_sec;
}
inline bool is_valid_policy_b3(int policy) {
    return 0 <= policy && policy < HW2_B3 && !(INVALID_MASK_B3 & (1ULL << policy));
}

inline bool is_valid_score_b3(int score) {
    return -SCORE_MAX_B3 <= score && score <= SCORE_MAX_B3;
}

inline bool is_black_like_char_b3(char c) {
    return c == 'B' || c == 'b' || c == 'X' || c == 'x' || c == '0' || c == '*';
}

inline bool is_white_like_char_b3(char c) {
    return c == 'W' || c == 'w' || c == 'O' || c == 'o' || c == '1';
}

inline bool is_vacant_like_char_b3(char c) {
    return c == '-' || c == '.';
}

inline bool is_pass_like_str_b3(std::string s) {
    return s == "PA" || s == "pa" || s == "PS" || s == "ps";
}

inline bool is_coord_like_chars_b3(char c1, char c2) {
    c1 = c1 | 0x20;
    return 'a' <= c1 && c1 <= 'h' && '1' <= c2 && c2 <= '8';
}

inline int get_coord_from_chars_b3(char c1, char c2) {
    c1 = c1 | 0x20;
    int y = c2 - '1';
    int x = c1 - 'a';
    int idx = HW2_M1_B3 - (y * HW_B3 + x);
    return (INVALID_MASK_B3 & (1ULL << idx)) ? -1 : idx;
}

/*
    @brief Generate coordinate in string

    @param idx                  index of the coordinate
    @return coordinate as string
*/
std::string idx_to_coord_b3(int idx) {
    if (idx < 0 || HW2_B3 <= idx || (INVALID_MASK_B3 & (1ULL << idx)))
        return "??";
    int y = HW_M1_B3 - idx / HW_B3;
    int x = HW_M1_B3 - idx % HW_B3;
    const std::string x_coord = "abcdefgh";
    return x_coord[x] + std::to_string(y + 1);
}

/*
    @brief Generate time in string

    @param t                    time in [ms]
    @return time with ms as string
*/
std::string ms_to_time_b3(uint64_t t) {
    std::string res;
    uint64_t hour = t / (1000 * 60 * 60);
    t %= 1000 * 60 * 60;
    uint64_t minute = t / (1000 * 60);
    t %= 1000 * 60;
    uint64_t second = t / 1000;
    uint64_t msecond = t % 1000;
    std::ostringstream hour_s;
    hour_s << std::right << std::setw(3) << std::setfill('0') << hour;
    res += hour_s.str();
    res += ":";
    std::ostringstream minute_s;
    minute_s << std::right << std::setw(2) << std::setfill('0') << minute;
    res += minute_s.str();
    res += ":";
    std::ostringstream second_s;
    second_s << std::right << std::setw(2) << std::setfill('0') << second;
    res += second_s.str();
    res += ".";
    std::ostringstream msecond_s;
    msecond_s << std::right << std::setw(3) << std::setfill('0') << msecond;
    res += msecond_s.str();
    return res;
}

/*
    @brief Generate time in string

    @param t                    time in [ms]
    @return time as string
*/
std::string ms_to_time_short_b3(uint64_t t) {
    std::string res;
    uint64_t hour = t / (1000 * 60 * 60);
    t -= hour * 1000 * 60 * 60;
    uint64_t minute = t / (1000 * 60);
    t -= minute * 1000 * 60;
    uint64_t second = t / 1000;
    t -= second * 1000;
    std::ostringstream hour_s;
    hour_s << std::right << std::setw(3) << std::setfill('0') << hour;
    res += hour_s.str();
    res += ":";
    std::ostringstream minute_s;
    minute_s << std::right << std::setw(2) << std::setfill('0') << minute;
    res += minute_s.str();
    res += ":";
    std::ostringstream second_s;
    second_s << std::right << std::setw(2) << std::setfill('0') << second;
    res += second_s.str();
    return res;
}
