package org.example;

public interface Signature {
    void generateKeys(); //sử dụng để tạo cặp khóa: khóa công khai và khóa cá nhân.
    // Các lớp triển khai interface này sẽ cung cấp logic để tạo các khóa này.

    byte[] getPublicKey(); //Phương thức trả về khóa công khai dưới dạng mảng byte.
    byte[] getPrivateKey(); //Phương thức trả về khóa cá nhân dưới dạng mảng byte.
    void setKeys(byte[] publicKey, byte[] privateKey); //Phương thức này nhận vào hai đối số là mảng byte đại diện
    // cho khóa công khai và khóa cá nhân và thiết lập các khóa này.

    byte[][] sign(byte[] message); //Phương thức này nhận vào một mảng byte đại diện cho thông điệp cần ký
//    và trả về một mảng 2 chiều byte đại diện cho chữ ký của thông điệp đó.
    boolean verify(byte[] message, byte[][] sign); // Phương thức này nhận vào một mảng byte đại diện cho thông điệp và
    // một mảng 2 chiều byte đại diện cho chữ ký của thông điệp đó.
    // Nó sẽ kiểm tra xem chữ ký có hợp lệ hay không đối với thông điệp đã cho và trả về giá trị true nếu hợp lệ và false nếu không hợp lệ
}
