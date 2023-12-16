#include <cassert>
#include <compoundfilereader.h>
#include <utf.h>
#include <string.h>
#include <stdio.h>
#include <memory>
#include <iostream>
#include <iomanip>
#include <limits>
#include <variant>
#include <zlib.h>
#include <openssl/aes.h>
#include "hwp.hpp"
#include "cxxopts.hpp"
#include "genkey.h"
#include "decrypt.hpp"

using namespace std;

void AES_decrypt(const unsigned char* encryptedMessage, unsigned char* key, unsigned char* decryptedMessage) {
    AES_KEY aesKey;
    AES_set_decrypt_key(key, 128, &aesKey);
    AES_ecb_encrypt(encryptedMessage, decryptedMessage, &aesKey, AES_DECRYPT);
}

void ShowUsage() {
    cout <<
            "usage:\n"
            "cfb list FILENAME\n"
            "cfb dump [-r] FILENAME STREAM_PATH\n"
            "cfb info FILENAME\n"
            "cfb info FILENAME STREAM_PATH\n"
            << endl;
}

void DumpBuffer(const void* buffer, size_t len) {
    const unsigned char* str = static_cast<const unsigned char *>(buffer);
    for (size_t i = 0; i < len; i++) {
        if (i > 0 && i % 16 == 0)
            cout << endl;
        cout << setw(2) << setfill('0') << hex << static_cast<int>(str[i]) << ' ';
    }
    cout << endl;
}

void DumpText(const char* buffer, size_t len) {
    cout << std::string(buffer, len) << endl;
}

std::vector<uint8_t> decompressData(const uint8_t* data, size_t length) {
    std::vector<uint8_t> decompressedData;
    z_stream strm = {0};
    strm.total_in = strm.avail_in = length;
    strm.next_in = (Bytef *) data;

    // Initialize the output buffer size and the z_stream
    size_t outputBufferSize = length * 2; // Initial estimate for the output buffer size
    std::vector<uint8_t> outputBuffer(outputBufferSize);

    if (inflateInit2(&strm, -MAX_WBITS) != Z_OK) {
        throw std::runtime_error("Failed to initialize zlib decompression");
    }

    int ret;
    do {
        strm.avail_out = outputBufferSize;
        strm.next_out = outputBuffer.data();

        ret = inflate(&strm, Z_NO_FLUSH);
        assert(ret != Z_STREAM_ERROR); // State not clobbered

        switch (ret) {
            case Z_NEED_DICT:
                ret = Z_DATA_ERROR; // And fall through
            case Z_DATA_ERROR:
            case Z_MEM_ERROR:
                inflateEnd(&strm);
                throw std::runtime_error("zlib decompression error");
        }

        size_t have = outputBufferSize - strm.avail_out;
        decompressedData.insert(decompressedData.end(), outputBuffer.begin(), outputBuffer.begin() + have);
    } while (strm.avail_out == 0);

    inflateEnd(&strm);

    return decompressedData;
}

struct HwpHeader {
    unsigned int versionMM;
    unsigned int versionnn;
    unsigned int versionPP;
    unsigned int versionrr;
    bool compressed;
    bool encrypted;
    bool distributed;
    bool script;
    bool drm;
    bool xmltemplate;
    bool history;
    bool signature;
    bool certencrypt;
    bool signature2;
    bool drm2;
    bool ccl;
    bool mobile;
    bool personalinfo;
    bool trackchange;
    bool kogl;
    bool video;
    bool toc;
    bool ccl2;
    bool copylimit;
    bool copylimit2;
    unsigned int encryptVersion;
    unsigned int licenseCountry;
};

HwpHeader DumpHwpHeader(const char* buffer, size_t len) {
    // BYTE array[32] 32 signature. 문서 파일은 "HWP Document File"
    // DWORD 4 파일 버전. 0xMMnnPPrr의 형태(예 5.0.3.0) § MM: 문서 형식의 구조가 완전히 바뀌는 것을 나타냄. 숫
    // 자가 다르면 구 버전과 호환 불가능. § nn: 큰 구조는 동일하나, 큰 변화가 있는 것을 나타냄. 숫
    // 자가 다르면 구 버전과 호환 불가능. § PP: 구조는 동일, Record가 추가되었거나, 하위 버전에서
    // 호환되지 않는 정보가 추가된 것을 나타냄. 숫자가 달라도
    // 구 버전과 호환 가능. § rr: Record에 정보들이 추가된 것을 나타냄. 숫자가 달라
    // 도 구 버전과 호환 가능.
    // DWORD 4 속성
    // bit 0 압축 여부
    // bit 1 암호 설정 여부
    // bit 2 배포용 문서 여부
    // bit 3 스크립트 저장 여부
    // bit 4 DRM 보안 문서 여부
    // bit 5 XMLTemplate 스토리지 존재 여부
    // bit 6 문서 이력 관리 존재 여부
    // bit 7 전자 서명 정보 존재 여부
    // bit 8 공인 인증서 암호화 여부
    // bit 9 전자 서명 예비 저장 여부
    // bit 10 공인 인증서 DRM 보안 문서 여부
    // bit 11 CCL 문서 여부
    // bit 12 모바일 최적화 여부
    // bit 13 개인 정보 보안 문서 여부
    // bit 14 변경 추적 문서 여부
    // bit 15 공공누리(KOGL) 저작권 문서
    // bit 16 비디오 컨트롤 포함 여부
    // bit 17 차례 필드 컨트롤 포함 여부
    // bit 18～31 예약
    // DWORD 4  속성
    // bit 0 CCL, 공공누리 라이선스 정보
    // bit 1 복제 제한 여부
    // bit 2 동일 조건 하에 복제 허가 여부
    // (복제 제한인 경우 무시)
    // bit 3～31 예약
    // DWORD 4 EncryptVersion
    // 0 : None
    // § 1 : (글 2.5 버전 이하) § 2 : (글 3.0 버전 Enhanced) § 3 : (글 3.0 버전 Old) § 4 : (글 7.0 버전 이후)
    // BYTE 1  공공누리(KOGL) 라이선스 지원 국가
    // § 6 : KOR
    // § 15 : US
    // BYTE array[207] 207 예약
    cout << "HWP Header" << endl;
    cout << "signature: " << std::string(buffer, 32) << endl;
    auto version = *reinterpret_cast<const uint32_t *>(buffer + 32);
    auto versionMM = (version >> 24) & 0xff;
    auto versionnn = (version >> 16) & 0xff;
    auto versionPP = (version >> 8) & 0xff;
    auto versionrr = version & 0xff;
    cout << "version: " << std::dec << versionMM << "." << versionnn << "." << versionPP << "." << versionrr << endl;
    auto property = *reinterpret_cast<const uint32_t *>(buffer + 36);
    bool compressed = (property & 0x1) != 0;
    bool encrypted = (property & 0x2) != 0;
    bool distributed = (property & 0x4) != 0;
    bool script = (property & 0x8) != 0;
    bool drm = (property & 0x10) != 0;
    bool xmltemplate = (property & 0x20) != 0;
    bool history = (property & 0x40) != 0;
    bool signature = (property & 0x80) != 0;
    bool certencrypt = (property & 0x100) != 0;
    bool signature2 = (property & 0x200) != 0;
    bool drm2 = (property & 0x400) != 0;
    bool ccl = (property & 0x800) != 0;
    bool mobile = (property & 0x1000) != 0;
    bool personalinfo = (property & 0x2000) != 0;
    bool trackchange = (property & 0x4000) != 0;
    bool kogl = (property & 0x8000) != 0;
    bool video = (property & 0x10000) != 0;
    bool toc = (property & 0x20000) != 0;
    cout << "property: " << std::hex << property << endl;
    cout << "compressed: " << std::dec << compressed << endl;
    cout << "encrypted: " << std::dec << encrypted << endl;
    cout << "distributed: " << std::dec << distributed << endl;
    cout << "script: " << std::dec << script << endl;
    cout << "drm: " << std::dec << drm << endl;
    cout << "xmltemplate: " << std::dec << xmltemplate << endl;
    cout << "history: " << std::dec << history << endl;
    cout << "signature: " << std::dec << signature << endl;
    cout << "certencrypt: " << std::dec << certencrypt << endl;
    cout << "signature2: " << std::dec << signature2 << endl;
    cout << "drm2: " << std::dec << drm2 << endl;
    cout << "ccl: " << std::dec << ccl << endl;
    cout << "mobile: " << std::dec << mobile << endl;
    cout << "personalinfo: " << std::dec << personalinfo << endl;
    cout << "trackchange (변경 문서 추적): " << std::dec << trackchange << endl;
    cout << "kogl (공공누리 저작권 문서): " << std::dec << kogl << endl;
    cout << "video (비디오 컨트롤 포함 여부): " << std::dec << video << endl;
    cout << "toc (차례 필드 컨트롤 포함 여부): " << std::dec << toc << endl;

    auto property2 = *reinterpret_cast<const uint32_t *>(buffer + 40);
    bool ccl2 = (property2 & 0x1) != 0;
    bool copylimit = (property2 & 0x2) != 0;
    bool copylimit2 = (property2 & 0x4) != 0;
    cout << "property2: " << std::hex << property2 << endl;
    cout << "ccl2: " << std::dec << ccl2 << endl;
    cout << "copylimit: " << std::dec << copylimit << endl;
    cout << "copylimit2: " << std::dec << copylimit2 << endl;

    auto encryptVersion = *reinterpret_cast<const uint32_t *>(buffer + 44);
    switch (encryptVersion) {
        case 0:
            cout << "encrypt version: None" << endl;
            break;
        case 1:
            cout << "encrypt version: (한글 2.5 버전 이하)" << endl;
            break;
        case 2:
            cout << "encrypt version: (한글 3.0 버전 Enhanced)" << endl;
            break;
        case 3:
            cout << "encrypt version: (한글 3.0 버전 Old)" << endl;
            break;
        case 4:
            cout << "encrypt version: (한글 7.0 버전 이후)" << endl;
            break;
    }
    auto licenseCountry = *reinterpret_cast<const uint8_t *>(buffer + 48);
    if (licenseCountry == 6)
        cout << "license country: KOR" << endl;
    else if (licenseCountry == 15)
        cout << "license country: US" << endl;
    else if (licenseCountry != 0)
        cout << "license country: " << std::dec << licenseCountry << endl;
    DumpBuffer(buffer + 49, 207);
    return HwpHeader{
        versionMM,
        versionnn,
        versionPP,
        versionrr,
        compressed,
        encrypted,
        distributed,
        script,
        drm,
        xmltemplate,
        history,
        signature,
        certencrypt,
        signature2,
        drm2,
        ccl,
        mobile,
        personalinfo,
        trackchange,
        kogl,
        video,
        toc,
        ccl2,
        copylimit,
        copylimit2,
        encryptVersion,
        licenseCountry
    };
}


void processData(const uint8_t* data, uint32_t dataSize, uint32_t tagID, std::vector<TaggedRecord>& records) {
    TaggedRecord taggedRecord;
    taggedRecord.tagID = tagID;

    if (tagID == HWPTAG_DOCUMENT_PROPERTIES) {
        if (dataSize >= sizeof(hwp_document_properties)) {
            taggedRecord.record = *reinterpret_cast<const hwp_document_properties *>(data);
        }
    } else if (tagID == HWPTAG_ID_MAPPINGS) {
        if (dataSize >= sizeof(hwptag_id_mappings)) {
            taggedRecord.record = *reinterpret_cast<const hwptag_id_mappings *>(data);
        }
    } else if (tagID == HWPTAG_BIN_DATA) {
        if (dataSize >= sizeof(uint32_t)) {
            uint32_t binDataSize = *reinterpret_cast<const uint32_t *>(data);
            if (dataSize >= sizeof(uint32_t) + binDataSize) {
                // 바이너리 데이터 처리
            }
        }
    } else if (tagID == HWPTAG_PARA_HEADER) {
        if (dataSize >= sizeof(hwptag_para_header)) {
            taggedRecord.size = dataSize;
            taggedRecord.record = *reinterpret_cast<const hwptag_para_header *>(data);
        }
    } else if (tagID == HWPTAG_PARA_TEXT) {
        taggedRecord.record = hwptag_para_text();
        taggedRecord.size = dataSize;
        auto& paraText = get<hwptag_para_text>(taggedRecord.record);
        paraText.text = std::vector<uint16_t>(dataSize / sizeof(uint16_t));
        memcpy(paraText.text.data(), data, dataSize);
    } else if (tagID == HWPTAG_PARA_CHAR_SHAPE) {
        // 글자 모양 처리
    } else if (tagID == HWPTAG_PARA_LINE_SEG) {
        // 줄 단위 정보 처리
    } else if (tagID == HWPTAG_PARA_RANGE_TAG) {
        // 범위 태그 처리
    } else if (tagID == HWPTAG_CTRL_HEADER) {
        // 컨트롤 헤더 처리
    } else if (tagID == HWPTAG_LIST_HEADER) {
        // 리스트 헤더 처리
    } else if (tagID == HWPTAG_PAGE_DEF) {
        // 용지 정의 처리
    } else if (tagID == HWPTAG_FOOTNOTE_SHAPE) {
        // 각주/미주 모양 처리
    } else if (tagID == HWPTAG_PAGE_BORDER_FILL) {
        // 쪽 테두리/배경 처리
    } else if (tagID == HWPTAG_SHAPE_COMPONENT) {
        // 개체 구성요소 처리
    } else if (tagID == HWPTAG_TABLE) {
        // 표 처리
    } else if (tagID == HWPTAG_SHAPE_COMPONENT_LINE) {
        // 개체 구성요소 선 처리
    } else if (tagID == HWPTAG_SHAPE_COMPONENT_RECTANGLE) {
        // 개체 구성요소 사각형 처리
    } else if (tagID == HWPTAG_SHAPE_COMPONENT_ELLIPSE) {
        // 개체 구성요소 타원 처리
    } else if (tagID == HWPTAG_SHAPE_COMPONENT_ARC) {
        // 개체 구성요소 호 처리
    } else if (tagID == HWPTAG_SHAPE_COMPONENT_POLYGON) {
        // 개체 구성요소 다각형 처리
    } else if (tagID == HWPTAG_SHAPE_COMPONENT_CURVE) {
        // 개체 구성요소 곡선 처리
    } else if (tagID == HWPTAG_SHAPE_COMPONENT_OLE) {
        // 개체 구성요소 OLE 처리
    } else if (tagID == HWPTAG_SHAPE_COMPONENT_PICTURE) {
        // 개체 구성요소 그림 처리
    } else if (tagID == HWPTAG_SHAPE_COMPONENT_CONTAINER) {
        // 개체 구성요소 컨테이너 처리
    } else if (tagID == HWPTAG_CTRL_DATA) {
        // 컨트롤 데이터 처리
    } else if (tagID == HWPTAG_EQEDIT) {
        // 수식 처리
    } else if (tagID == HWPTAG_SHAPE_COMPONENT_TEXTART) {
        // 개체 구성요소 텍스트아트 처리
    } else if (tagID == HWPTAG_FORM_OBJECT) {
        // 양식 개체 처리
    } else if (tagID == HWPTAG_MEMO_SHAPE) {
        // 메모 모양 처리
    } else if (tagID == HWPTAG_MEMO_LIST) {
        // 메모 리스트 처리
    } else if (tagID == HWPTAG_CHART_DATA) {
        // 차트 데이터 처리
    } else if (tagID == HWPTAG_VIDEO_DATA) {
        // 비디오 데이터 처리
    } else if (tagID == HWPTAG_SHAPE_COMPONENT_UNKNOWN) {
        // 개체 구성요소 알 수 없는 개체 처리
    } else {
        // 알 수 없는 태그 ID 처리
    }
    // 다른 태그 ID들에 대한 처리...

    records.push_back(std::move(taggedRecord));
}


vector<TaggedRecord> parseRecords(const uint8_t* data, size_t length) {
    size_t offset = 0;
    std::vector<TaggedRecord> records = std::vector<TaggedRecord>();
    while (offset < length) {
        const auto* header = reinterpret_cast<const RecordHeader *>(data + offset);
        // const auto headerDword = *reinterpret_cast<const uint32_t *>(data + offset);
        // cout << "HeaderDword: " << headerDword << endl;
        // cout << "TagID: " << header->TagID << endl;
        // cout << "Level: " << header->Level << endl;
        // cout << "Size: " << header->Size << endl;

        uint32_t dataSize = header->Size;
        if (dataSize == 4095) {
            dataSize = *reinterpret_cast<const uint32_t *>(data + offset + sizeof(RecordHeader));
            offset += sizeof(uint32_t);
        }

        processData(data + offset + sizeof(RecordHeader), dataSize, header->TagID, records);

        offset += sizeof(RecordHeader) + dataSize;
    }
    return records;
}

// 방문자 클래스 정의
class RecordVisitor {
public:
    void operator()(const hwp_document_properties& rec) const {
        std::cout << "Processing hwp_document_properties" << std::endl;
        cout << "zoneCount: " << rec.zoneCount << endl;
        cout << "pageStartNumber: " << rec.pageStartNumber << endl;
        cout << "footnoteStartNumber: " << rec.footnoteStartNumber << endl;
        cout << "endnoteStartNumber: " << rec.endnoteStartNumber << endl;
        cout << "pictureStartNumber: " << rec.pictureStartNumber << endl;
        cout << "tableStartNumber: " << rec.tableStartNumber << endl;
        cout << "equationStartNumber: " << rec.equationStartNumber << endl;
        cout << "listID: " << rec.listID << endl;
        cout << "paragraphID: " << rec.paragraphID << endl;
        cout << "paragraphPosition: " << rec.paragraphPosition << endl;
    }

    void operator()(const hwptag_id_mappings& rec) const {
        std::cout << "Processing hwptag_id_mappings" << std::endl;
        for (int i = 0; i < 18; i++) {
            cout << "idMappings[" << i << "]: " << rec.idMappings[i] << endl;
        }
    }

    void operator()(const hwptag_bin_data& rec) const {
        std::cout << "Processing hwptag_bin_data" << std::endl;
    }

    void operator()(const hwptag_para_header& rec) const {
        std::cout << "Processing hwptag_para_header" << std::endl;
        cout << "text: " << rec.text << endl;
        cout << "controlMask: " << rec.controlMask << endl;
        cout << "paragraphShapeID: " << rec.paragraphShapeID << endl;
        cout << "paragraphStyleID: " << rec.paragraphStyleID << endl;
        cout << "divideSort: " << rec.divideSort << endl;
        cout << "charShapeCount: " << rec.charShapeCount << endl;
        cout << "rangeTagCount: " << rec.rangeTagCount << endl;
        cout << "alignCount: " << rec.alignCount << endl;
        cout << "instanceID: " << rec.instanceID << endl;
        cout << "trackChangeMerge: " << rec.trackChangeMerge << endl;
    }

    void operator()(const hwptag_para_text& rec) const {
        std::cout << "Processing hwptag_para_text" << std::endl;
        // Read 19 * 2 bytes and cast as wchar_t
        // reinterpret_cast is not allowed.
        // const wchar_t* text = reinterpret_cast<const wchar_t*>(rec.text);
        for (const auto& ch: rec.text) {
            if (ch < 32) {
                cout << "Control character" << endl;
            }
            cout << ch << ";";
        }
        cout << endl;
    }
};

vector<unsigned char> DecryptHwpSection(const string& password, const char* data, const size_t len) {
    // genkey 함수를 사용하여 키 생성
    std::string pwd = genkey(password);
    cout << "Input password: " << password << endl; // "1234567890123456
    cout << "Generated Key: " << pwd << endl; // "1234567890123456"

    // pad 함수를 사용하여 데이터 패딩
    std::vector<unsigned char> paddedData = pad(std::vector<unsigned char>(data, data + len));

    // gogo 함수를 사용하여 데이터 복호화
    return gogo(std::vector<unsigned char>(pwd.begin(), pwd.end()), paddedData, false);
}


void inflate_section(const char* buffer, size_t len, bool compressed, bool encrypted, const string& password, vector<uint8_t>& decompressed) {
    vector<uint8_t> decrypted;
    if (encrypted) {
        decrypted = DecryptHwpSection(password, buffer, len);
        cout << "Decrypted" << endl;
    } else {
        decrypted = vector<uint8_t>(buffer, buffer + len);
    }
    if (compressed) {
        decompressed = decompressData(decrypted.data(), decrypted.size());
        cout << "Decompressed" << endl;
    } else {
        decompressed = decrypted;
    }
}

void DumpDocInfo(const char* buffer, size_t len, bool compressed, bool encrypted, const string& password) {
    // 본문에 사용 중인 글꼴, 글자 속성, 문단 속성, 탭, 스타일 등에 문서 내 공통으로 사용되는 세부 정보를 담고 있다.
    // Tag ID 길이(바이트) 레벨 설명
    // HWPTAG_DOCUMENT_PROPERTIES 30 0 문서 속성(표 14 참조)
    // HWPTAG_ID_MAPPINGS 32 0 아이디 매핑 헤더(표 15 참조)
    // HWPTAG_BIN_DATA 가변 1 바이너리 데이터(표 17 참조)
    // HWPTAG_FACE_NAME 가변 1 글꼴(표 19 참조)
    // HWPTAG_BORDER_FILL 가변 1 테두리/배경(표 23 참조)
    // HWPTAG_CHAR_SHAPE 72 1 글자 모양(표 33 참조)
    // HWPTAG_TAB_DEF 14 1 탭 정의(표 36 참조)
    // HWPTAG_NUMBERING 가변 1 문단 번호(표 38 참조)
    // HWPTAG_BULLET 10 1 글머리표(표 42 참조)
    // HWPTAG_PARA_SHAPE 54 1 문단 모양(표 43 참조)
    // HWPTAG_STYLE 가변 1 스타일(표 47 참조)
    // HWPTAG_MEMO_SHAPE 22 1 메모 모양
    // HWPTAG_TRACK_CHANGE_AUTHOR 가변 1 변경 추적 작성자
    // HWPTAG_TRACK_CHANGE 가변 1 변경 추적 내용 및 모양
    // HWPTAG_DOC_DATA 가변 0 문서 임의의 데이터(표 49 참조)
    // HWPTAG_FORBIDDEN_CHAR 가변 0 금칙처리 문자
    // HWPTAG_COMPATIBLE_DOCUMENT 4 0 호환 문서(표 54 참조)
    // HWPTAG_LAYOUT_COMPATIBILITY 20 1 레이아웃 호환성(표 56 참조)
    // HWPTAG_DISTRIBUTE_DOC_DATA 256 0 배포용 문서
    // HWPTAG_TRACKCHANGE 1032 1 변경 추적 정보
    vector<uint8_t> decompressed;
    inflate_section(buffer, len, compressed, encrypted, password, decompressed);
    auto records = parseRecords(decompressed.data(), decompressed.size());
    // 각 레코드 처리
    for (const auto& taggedRecord: records) {
        std::visit(RecordVisitor(), taggedRecord.record);
    }
}

void DumpHwpBody(const char* buffer, size_t len, bool compressed, bool encrypted, const string& password) {
    // inflate section
    vector<uint8_t> decompressed;
    inflate_section(buffer, len, compressed, encrypted, password, decompressed);
    auto records = parseRecords(decompressed.data(), decompressed.size());
    // 각 레코드 처리
    for (const auto& taggedRecord: records) {
        std::cout << "Size:" << taggedRecord.size << std::endl;
        std::visit(RecordVisitor(), taggedRecord.record);
    }
}

void OutputFileInfo(const CFB::CompoundFileReader& reader) {
    const CFB::COMPOUND_FILE_HDR* hdr = reader.GetFileInfo();
    cout
            << "file version: " << hdr->majorVersion << "." << hdr->minorVersion << endl
            << "difat sector: " << hdr->numDIFATSector << endl
            << "directory sector: " << hdr->numDirectorySector << endl
            << "fat sector: " << hdr->numFATSector << endl
            << "mini fat sector: " << hdr->numMiniFATSector << endl;
}

void OutputEntryInfo(const CFB::CompoundFileReader& reader, const CFB::COMPOUND_FILE_ENTRY* entry) {
    cout
            << "entry type: " << (reader.IsPropertyStream(entry)
                                      ? "property"
                                      : (reader.IsStream(entry) ? "stream" : "directory")) << endl
            << "color flag: " << entry->colorFlag << endl
            << "creation time: " << entry->creationTime << endl
            << "modified time: " << entry->modifiedTime << endl
            << "child ID: " << entry->childID << endl
            << "left sibling ID: " << entry->leftSiblingID << endl
            << "right sibling ID: " << entry->startSectorLocation << entry->rightSiblingID << endl
            << "start sector: " << entry->startSectorLocation << endl
            << "size: " << entry->size << endl;
}

vector<CFB::utf16string> ListDirectory(const CFB::CompoundFileReader& reader) {
    vector<CFB::utf16string> dirs;
    reader.EnumFiles(reader.GetRootEntry(), -1,
                     [&](const CFB::COMPOUND_FILE_ENTRY* entry, const CFB::utf16string& dir, int level)-> void {
                         bool isDirectory = !reader.IsStream(entry);
                         std::string name = UTF16ToUTF8(entry->name);
                         std::string indentstr(level * 4 - 4, ' ');
                         cout << indentstr.c_str() << (isDirectory ? "[" : "") << name.c_str() << (
                             isDirectory ? "]" : "") << endl;
                         dirs.push_back(dir);
                     });
    return dirs;
}

const CFB::COMPOUND_FILE_ENTRY* FindStream(const CFB::CompoundFileReader& reader, const char* streamName,
                                           const CFB::COMPOUND_FILE_ENTRY* entry) {
    const CFB::COMPOUND_FILE_ENTRY* ret = nullptr;
    reader.EnumFiles(entry, -1,
                     [&](const CFB::COMPOUND_FILE_ENTRY* entry, const CFB::utf16string& u16dir, int level)-> void {
                         if (reader.IsStream(entry)) {
                             std::string name = UTF16ToUTF8(entry->name);
                             if (u16dir.length() > 0) {
                                 std::string dir = UTF16ToUTF8(u16dir.c_str());
                                 if (strncmp(streamName, dir.c_str(), dir.length()) == 0 &&
                                     streamName[dir.length()] == '\\' &&
                                     strcmp(streamName + dir.length() + 1, name.c_str()) == 0) {
                                     ret = entry;
                                 }
                             } else {
                                 if (strcmp(streamName, name.c_str()) == 0) {
                                     ret = entry;
                                 }
                             }
                         }
                     });
    return ret;
}

void DumpHwpFile(const CFB::CompoundFileReader& reader, const vector<CFB::utf16string>& dirs, const string& password) {
    // First dump FileHeader
    const CFB::COMPOUND_FILE_ENTRY* entry = FindStream(reader, "FileHeader", reader.GetRootEntry());
    if (entry == nullptr) {
        cerr << "error: FileHeader doesn't exist" << endl;
        return;
    }
    cout << "FileHeader size: " << entry->size << endl;
    if (entry->size > std::numeric_limits<size_t>::max()) {
        cerr << "error: FileHeader too large" << endl;
        return;
    }
    size_t size = static_cast<size_t>(entry->size);
    std::unique_ptr<char> content(new char[size]);
    reader.ReadFile(entry, 0, content.get(), size);
    const auto& header = DumpHwpHeader(content.get(), size);
    if (header.encrypted) {
        cout << "The file is encrypted" << endl;
    }
    if (header.compressed) {
        cout << "The file is compressed" << endl;
    }
    // Dump DocInfo
    entry = FindStream(reader, "DocInfo", reader.GetRootEntry());
    if (entry == nullptr) {
        cerr << "error: DocInfo doesn't exist" << endl;
        return;
    }
    cout << "size: " << entry->size << endl;
    if (entry->size > std::numeric_limits<size_t>::max()) {
        cerr << "error: DocInfo too large" << endl;
        return;
    }
    size = static_cast<size_t>(entry->size);
    content.reset(new char[size]);
    reader.ReadFile(entry, 0, content.get(), size);
    DumpDocInfo(content.get(), size, header.compressed, header.encrypted, password);
    // Dump BodyText
    // DocInfo has number of sections in the document
    // BodyText\Section0
    // BodyText\Section1
    // ...
    // BodyText\SectionN
    // Dump each section
    for (int i = 0; i < 1; i++) {
        std::stringstream ss;
        ss << "BodyText\\Section" << i;
        entry = FindStream(reader, ss.str().c_str(), reader.GetRootEntry());
        if (entry == nullptr) {
            cerr << "error: " << ss.str() << " doesn't exist" << endl;
            return;
        }
        cout << "size: " << entry->size << endl;
        if (entry->size > std::numeric_limits<size_t>::max()) {
            cerr << "error: " << ss.str() << " too large" << endl;
            return;
        }
        size = static_cast<size_t>(entry->size);
        content.reset(new char[size]);
        reader.ReadFile(entry, 0, content.get(), size);
        DumpHwpBody(content.get(), size, header.compressed, header.encrypted, password);
    }
}

int new_main(string cmd, string file, string streamName, bool dumpraw, string password) {
    FILE* fp = fopen(file.c_str(), "rb");
    if (fp == NULL) {
        cerr << "read file error" << endl;
        return 1;
    }
    fseek(fp, 0, SEEK_END);
    size_t len = ftell(fp);
    std::unique_ptr<unsigned char> buffer(new unsigned char[len]);
    fseek(fp, 0, SEEK_SET);

    len = fread(buffer.get(), 1, len, fp);
    CFB::CompoundFileReader reader(buffer.get(), len);
    if (cmd == "list") {
        ListDirectory(reader);
    } else if (cmd == "dump") {
        if (streamName.empty()) {
            // Dump all the hwp file
            OutputFileInfo(reader);
            auto dirs = ListDirectory(reader);
            DumpHwpFile(reader, dirs, password);
            return 0;
        }
        const CFB::COMPOUND_FILE_ENTRY* entry = FindStream(reader, streamName.c_str(), reader.GetRootEntry());
        if (entry == nullptr) {
            cerr << "error: stream doesn't exist" << endl;
            return 2;
        }
        cout << "size: " << entry->size << endl;
        if (entry->size > std::numeric_limits<size_t>::max()) {
            cerr << "error: stream too large" << endl;
            return 2;
        }
        size_t size = static_cast<size_t>(entry->size);
        std::unique_ptr<char> content(new char[size]);
        reader.ReadFile(entry, 0, content.get(), size);
        if (dumpraw)
            DumpText(content.get(), size);
        else if (streamName == "FileHeader")
            DumpHwpHeader(content.get(), size);
        else if (streamName == "DocInfo") {
            DumpBuffer(content.get(), size);
            DumpDocInfo(content.get(), size, false, false, password);
        } else if (streamName == "BodyText\\Section0") {
            // TODO: Check pattern
            DumpBuffer(content.get(), size);
            DumpHwpBody(content.get(), size, false, false, password);
        } else {
            DumpBuffer(content.get(), size);
        }
    } else if (cmd == "info") {
        if (streamName.empty()) {
            OutputFileInfo(reader);
        } else {
            const CFB::COMPOUND_FILE_ENTRY* entry = FindStream(reader, streamName.c_str(), reader.GetRootEntry());
            if (entry == NULL) {
                cerr << "error: stream doesn't exist" << endl;
                return 2;
            }
            OutputEntryInfo(reader, entry);
        }
    }
    return 0;
}


int main(int argc, char* argv[]) {
    cxxopts::Options options("HwpDump", "Dump a HWP file");
    options.add_options()
            ("cmd", "The command to execute", cxxopts::value<std::string>())
            ("file", "The HWP file to dump", cxxopts::value<std::string>())
            ("d,debug", "Enable debugging") // a bool parameter
            ("r,raw", "Dump raw value") // a bool parameter
            ("s,stream", "The stream name to dump", cxxopts::value<std::string>()->default_value(""))
            ("p,password", "The password to use if encrypted", cxxopts::value<std::string>()->default_value(""))
            // ("i,integer", "Int param", cxxopts::value<int>())
            ("v,verbose", "Verbose output", cxxopts::value<bool>()->default_value("false"));
    options.parse_positional({"cmd", "file"});
    auto parsed_options = options.parse(argc, argv);
    if (parsed_options.count("help")) {
        std::cout << options.help() << std::endl;
        ShowUsage();
        exit(0);
    }
    auto cmd = parsed_options["cmd"].as<std::string>();
    auto filename = parsed_options["file"].as<std::string>();
    auto debug = parsed_options["debug"].as<bool>();
    auto raw = parsed_options["raw"].as<bool>();
    auto stream = parsed_options["stream"].as<std::string>();
    auto password = parsed_options["password"].as<std::string>();
    try {
        return new_main(cmd, filename, stream, raw, password);
    } catch (CFB::CFBException& e) {
        cerr << "error: " << e.what() << endl;
        return 2;
    }
}
