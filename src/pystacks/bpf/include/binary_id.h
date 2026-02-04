// Copyright (c) Meta Platforms, Inc. and affiliates.

#ifndef __BPF_LIB_BINARY_ID_H__
#define __BPF_LIB_BINARY_ID_H__

#ifdef __cplusplus

#include <fcntl.h>
#include <linux/kdev_t.h> // for MKDEV
#include <sys/stat.h>
#include <unistd.h>
#include <ostream>
#include <string>

namespace facebook::strobelight::bpf_lib {

#else

#include <vmlinux.h>
#endif // __cplusplus

// Combination of inode and device ID, as returned by fstat(), uniquely
// identifies a binary file
struct bpf_lib_binary_id {
  ino_t inode;
  uint64_t dev;

#ifdef __cplusplus
  bpf_lib_binary_id() : inode(0), dev(0) {}
  bpf_lib_binary_id(dev_t dev, ino_t inode) : inode(inode), dev(dev) {}
  bpf_lib_binary_id(dev_t major, dev_t minor, ino_t inode)
      : inode(inode), dev(MKDEV(major, minor)) {}

  explicit bpf_lib_binary_id(const std::string& path) : inode(0), dev(0) {
    int fd = ::open(path.c_str(), O_PATH);
    if (fd != -1) {
      struct stat st;
      if (::fstat(fd, &st) == 0) {
        inode = st.st_ino;
        dev = st.st_dev;
      }
      ::close(fd);
    }
  }

  bool empty() const {
    return inode == 0 && dev == 0;
  }

  bpf_lib_binary_id(const bpf_lib_binary_id&) = default;
  bpf_lib_binary_id& operator=(const bpf_lib_binary_id&) = default;

  bool operator==(const bpf_lib_binary_id& that) const {
    return dev == that.dev && inode == that.inode;
  }

  bool operator!=(const bpf_lib_binary_id& that) const {
    return dev != that.dev || inode != that.inode;
  }

  bool operator<(const bpf_lib_binary_id& that) const {
    if (dev != that.dev) {
      return dev < that.dev;
    }
    return inode < that.inode;
  }

  bool operator>(const bpf_lib_binary_id& that) {
    return that < *this;
  }

  friend std::ostream& operator<<(
      std::ostream& out,
      const bpf_lib_binary_id& binary) {
    return out << "(dev=0x" << std::hex << binary.dev << std::dec
               << ",inode=" << binary.inode << ")";
  }
#endif // __cplusplus
};

inline __attribute__((always_inline)) struct bpf_lib_binary_id make_binary_id(
    dev_t dev,
    ino_t inode) {
  struct bpf_lib_binary_id id = {0, 0};
  id.dev = dev;
  id.inode = inode;
  return id;
}

#ifdef __cplusplus
} // namespace facebook::strobelight::bpf_lib

namespace std {

template <>
struct hash<struct facebook::strobelight::bpf_lib::bpf_lib_binary_id> {
  // taken from boost::hash_combine
  template <class T>
  inline static void hash_combine(size_t& seed, const T& v) {
    std::hash<T> hasher;
    seed ^= hasher(v) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
  }

  size_t operator()(
      const struct facebook::strobelight::bpf_lib::bpf_lib_binary_id& v) const {
    size_t hash = 0;
    hash_combine(hash, v.dev);
    hash_combine(hash, v.inode);
    return hash;
  }
};

} // namespace std
#endif // __cplusplus

#endif // __BPF_LIB_BINARY_ID_H__
