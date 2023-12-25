package org.example;

public interface Hash {
    byte[] getDigest(byte[] message); //nhận dữ liệu dạng mảng byte và trả về giá trị băm của dữ liệu đó dưới dạng mảng byte.
}
