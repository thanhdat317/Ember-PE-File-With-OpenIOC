<div align="center">
  <h1>🛡️ EMBER2024 Malware Scanner</h1>
  <p><strong>Công cụ quét mã độc mạnh mẽ chuyên dùng cho file PE chạy trên nền tảng AI mới nhất</strong></p>
</div>

<hr/>

## 📖 Giới thiệu (Overview)

**EMBER2024 Malware Scanner** là hệ thống bảo mật quét mã độc thông minh. Ứng dụng tập trung phân tích các file chuẩn Windows PE (như `.exe`, `.dll`, `.sys`) bằng trí tuệ nhân tạo.

Dự án này sử dụng mô hình học máy **LightGBM** mới nhất được đào tạo trên tập dữ liệu đồ sộ **EMBER2024** (được nghiên cứu và xuất bản năm 2024). Ứng dụng cung cấp giao diện trực quan ngay trên trình duyệt, không cần chạy file độc hại mà vẫn có thể phân tích cấu trúc để đưa ra tỷ lệ rủi ro một cách chính xác.

## ✨ Tính năng chính (Features)

- **🧠 Trí tuệ Nhân tạo hiện đại**: Ứng dụng trực tiếp model LightGBM mạnh mẽ của Bộ dữ liệu EMBER2024.
- **🔍 Quét mã tĩnh (Static Analysis)**: Nhận dạng rủi ro và mã độc cực nhanh mà KHÔNG CẦN CHẠY tệp độc hại trên máy (an toàn tuyệt đối).
- **🌐 Tích hợp VirusTotal**: Mở rộng phạm vi tìm kiếm mạng IOC và danh tiếng toàn cầu bằng cách kết nối API với VirusTotal.
- **📄 Xuất báo cáo OpenIOC XML**: Hệ thống tự động thiết lập và xuất báo cáo chuẩn IOC cho các chuyên gia an ninh mạng.
- **🖥️ Giao diện Streamlit dễ dùng**: Tải file lên và nhận diện trực quan với các thanh tiến trình rủi ro theo % mà không cần kiến thức chạy dòng lệnh.

## 🚀 Hướng Dẫn Cài Đặt và Chạy Trên Máy Tính Local (Installation)

Yêu cầu máy tính cài đặt sẵn Python (phiên bản 3.9 trở lên được khuyến nghị).

**1. Clone dự án về máy**
```bash
git clone https://github.com/thanhdat317/Ember-PE-File-With-OpenIOC.git
cd Ember-PE-File-With-OpenIOC
```

**2. Cài đặt các thư viện phụ thuộc cực kỳ thiết yếu**
```bash
pip install -r requirements.txt
```

**3. Chạy Ứng Dụng (Khởi tạo lần đầu)**
Ứng dụng sử dụng Streamlit làm máy chủ giao diện. Chạy lệnh sau trong terminal:
```bash
streamlit run app.py
```
> **Lưu ý quan trọng**: Ở lần khởi chạy ĐẦU TIÊN, vì các file mô hình AI (`EMBER2024_PE.model`) có dung lượng khá lớn nên ứng dụng sẽ **tự động tải mô hình** từ máy chủ gốc về thư mục `./models` (khoảng vài chục giây đến vài phút tùy mạng). Bạn chỉ cần chờ hệ thống báo xong là có thể sử dụng ở các lần sau.

## 🏁 Hướng Dẫn Sử Dụng trên trình duyệt

1. Truy cập vào đường link mà Terminal hiển thị (thường là `http://localhost:8501`).
2. **Kéo & Thả** hoặc chọn một file `.exe` / `.dll` đáng ngờ vào ô tải file.
3. Chờ công cụ xuất **% Mức độ Rủi ro (ML Score)**. 
   - Nếu tỷ lệ cao trên 70%, file có nguy cơ cao là mã độc (Malicious).
4. Bạn có thể nhập mã khóa ẩn API Key của **VirusTotal** vào thanh bên trái để quét file đó diện rộng trên toàn cầu miễn phí, qua đó trích xuất ra các IP và Domain nguy hiểm đi kèm.
5. Nhấn **Generate OpenIOC Report** để tải file chứng chi định kỳ rủi ro (.ioc) về máy.

## ☁️ Hướng Dẫn Deploy Lên Streamlit Cloud

Dự án này đã được tối ưu hóa đặc biệt để triển khai (Deploy) dễ dàng lên các nền tảng đám mây lớn như **Streamlit Community Cloud**:
- Github Repository của bạn không chứa file Model nặng, vì `app.py` đã được mã hóa tự động kéo mô hình về server lúc runtime.
- Tuy nhiên, hãy vào phần **Advanced Settings** lúc tạo app trên Streamlit Cloud, dán biến môi trường Python version `3.10` để tương thích cấu trúc của thư viện `thrember` tốt nhất.
