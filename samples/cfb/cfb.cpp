#include <compoundfilereader.h>
#include <utf.h>
#include <string.h>
#include <stdio.h>
#include <memory>
#include <iostream>
#include <iomanip>
#include <limits>
#include <variant>

using namespace std;

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

void DumpHwpHeader(const char* buffer, size_t len) {
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
}

# define HWPTAG_BEGIN 0x10
#pragma pack(push)
#pragma pack(1)
// 레코드 헤더의 크기는 32bits이고 TagID(10bits), Level(10bits), Size(12bits)로 구성된다.
// Tag ID : 레코드가 나타내는 데이터의 종류를 나타내는 태그이다. Tag ID에는 10 비트가 사용되므로 0x000 - 0x3FF까지 가능하다.
// 0x000 - 0x00F = 일반 레코드 태그가 아닌 특별한 용도로 사용한다.
// - 0x010 - 0x1FF = 한글에 의해 내부용으로 예약된 영역(HWPTAG_BEGIN = 0x010)
// - 0x200 - 0x3FF = 외부 어플리케이션이 사용할 수 있는 영역
// Level : 대부분 하나의 오브젝트는 여러 개의 레코드로 구성되는 것이 일반적이기 때문에 하나의
// 레코드가 아닌 "논리적으로 연관된 연속된 레코드"라는 개념이 필요하다. 레벨은 이와 같이 연관된
// 레코드의 논리적인 묶음을 표현하기 위한 정보이다. 스트림을 구성하는 모든 레코드는 계층 구조로
// 표현할 수 있는데, 레벨은 바로 이 계층 구조에서의 depth를 나타낸다.
// Size : 데이터 영역의 길이를 바이트 단위로 나타낸다. 12개의 비트가 모두 1일 때는 데이터 영역의
// 길이가 4095 바이트 이상인 경우로, 이때는 레코드 헤더에 연이어 길이를 나타내는 DWORD가
// 추가된다. 즉, 4095 바이트 이상의 데이터일 때 레코드는 다음과 같이 표현된다.
// 레코드 헤더(32bits) + 길이(32bits) + 데이터 영역(4095 바이트 이상)
typedef struct __attribute__((packed)) {
    uint32_t TagID: 10; // 10 bits for TagID
    uint32_t Level: 10; // 10 bits for Level
    uint32_t Size: 12; // 12 bits for Size
} RecordHeader;

# define HWPTAG_DOCUMENT_PROPERTIES HWPTAG_BEGIN // 문서 속성
# define HWPTAG_ID_MAPPINGS (HWPTAG_BEGIN + 1) // 아이디 매핑 헤더
# define HWPTAG_BIN_DATA (HWPTAG_BEGIN + 2) // 바이너리 데이터
# define HWPTAG_FACE_NAME (HWPTAG_BEGIN + 3) // 글꼴
# define HWPTAG_BORDER_FILL (HWPTAG_BEGIN + 4) // 테두리/배경
# define HWPTAG_CHAR_SHAPE (HWPTAG_BEGIN + 5) // 글자 모양
# define HWPTAG_TAB_DEF (HWPTAG_BEGIN + 6) // 탭 정의
# define HWPTAG_NUMBERING (HWPTAG_BEGIN + 7) // 문단 번호
# define HWPTAG_BULLET (HWPTAG_BEGIN + 8) // 글머리표
# define HWPTAG_PARA_SHAPE (HWPTAG_BEGIN + 9) // 문단 모양
# define HWPTAG_STYLE (HWPTAG_BEGIN + 10) // 스타일
# define HWPTAG_DOC_DATA (HWPTAG_BEGIN + 11) // 문서 임의의 데이터
# define HWPTAG_DISTRIBUTE_DOC_DATA (HWPTAG_BEGIN + 12) // 배포용 문서
# define HWPTAG_RESERVED (HWPTAG_BEGIN + 13) // 예약
# define HWPTAG_COMPATIBLE_DOCUMENT (HWPTAG_BEGIN + 14) // 호환 문서
# define HWPTAG_LAYOUT_COMPATIBILITY (HWPTAG_BEGIN + 15) // 레이아웃 호환성
# define HWPTAG_TRACKCHANGE (HWPTAG_BEGIN + 16) // 변경 추적 정보
# define HWPTAG_MEMO_SHAPE (HWPTAG_BEGIN + 76) // 메모 모양
# define HWPTAG_FORBIDDEN_CHAR (HWPTAG_BEGIN + 78) // 금칙처리 문자
# define HWPTAG_TRACK_CHANGE (HWPTAG_BEGIN + 80) // 변경 추적 내용 및 모양
# define HWPTAG_TRACK_CHANGE_AUTHOR (HWPTAG_BEGIN + 81) // 변경 추적 작성자


struct hwp_document_properties {
    // 자료형 길이(바이트) 설명
    // UINT16 2 구역 개수
    // 문서 내 각종 시작번호에 대한 정보
    // UINT16 2 페이지 시작 번호
    // UINT16 2 각주 시작 번호
    // UINT16 2 미주 시작 번호
    // UINT16 2 그림 시작 번호
    // UINT16 2 표 시작 번호
    // UINT16 2 수식 시작 번호
    // 문서 내 캐럿의 위치 정보
    // UINT32 4 리스트 아이디
    // UINT32 4 문단 아이디
    // UINT32 4 문단 내에서의 글자 단위 위치
    // 전체 길이 26
    uint16_t zoneCount;
    uint16_t pageStartNumber;
    uint16_t footnoteStartNumber;
    uint16_t endnoteStartNumber;
    uint16_t pictureStartNumber;
    uint16_t tableStartNumber;
    uint16_t equationStartNumber;
    uint32_t listID;
    uint32_t paragraphID;
    uint32_t paragraphPosition;
};

struct hwptag_id_mappings {
    // INT32 array[18] 72 아이디 매핑 개수(표 16 참조)
    // 전체 길이 72 doc version 에 따라 가변적
    int32_t idMappings[18];
};

struct hwptag_bin_data {
    // 그림, OLE 등의 바이너리 데이터 아이템에 대한 정보
    // UINT16  2 속성(표 18 참조)
    // WORD 2 Type이 "LINK"일 때, 연결 파일의 절대 경로 길이 (len1)
    // WCHAR array[len1] 2×len1 Type이 "LINK"일 때, 연결 파일의 절대 경로
    // WORD 2 Type이 "LINK"일 때, 연결 파일의 상대 경로 길이 (len2)
    // WCHAR array[len2] 2×len2 Type이 "LINK"일 때, 연결 파일의 상대 경로
    // UINT16 2 Type이 "EMBEDDING"이거나 "STORAGE"일 때, BINDATASTORAGE에 저장된 바이너리 데이터의 아이디
    // WORD 2 Type이 "EMBEDDING"일 때, 바이너리 데이터의 형식 이름의 길이 (len3)
    // WCHAR array[len3] 2×len3 Type이 "EMBEDDING"일 때 extension("." 제외)
    // 그림의 경우 jpg bmp gif
    // OLE의 경우 ole
    // 전체 길이 가변 10 + (2×len1) + (2×len2) + (2×len3) 바이트
};
#pragma pack(pop)

using RecordVariant = variant<hwp_document_properties, hwptag_id_mappings /* , 다른 타입들... */>;

// 레코드와 태그 ID를 함께 저장하는 래퍼 구조체
struct TaggedRecord {
    uint32_t tagID;
    RecordVariant record;
};

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
    }
    // 다른 태그 ID들에 대한 처리...

    records.push_back(std::move(taggedRecord));
}


vector<TaggedRecord> parseRecords(const uint8_t* data, size_t length) {
    size_t offset = 0;
    std::vector<TaggedRecord> records = std::vector<TaggedRecord>();
    while (offset < length) {
        const auto* header = reinterpret_cast<const RecordHeader *>(data + offset);

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
};


void DumpDocInfo(const char* buffer, size_t len) {
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
    auto records = parseRecords(reinterpret_cast<const uint8_t *>(buffer), len);
    // 각 레코드 처리
    for (const auto& taggedRecord: records) {
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

const void ListDirectory(const CFB::CompoundFileReader& reader) {
    reader.EnumFiles(reader.GetRootEntry(), -1,
                     [&](const CFB::COMPOUND_FILE_ENTRY* entry, const CFB::utf16string& dir, int level)-> void {
                         bool isDirectory = !reader.IsStream(entry);
                         std::string name = UTF16ToUTF8(entry->name);
                         std::string indentstr(level * 4 - 4, ' ');
                         cout << indentstr.c_str() << (isDirectory ? "[" : "") << name.c_str() << (
                             isDirectory ? "]" : "") << endl;
                     });
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


int main_internal(int argc, char* argv[]) {
    const char* cmd = nullptr;
    const char* file = nullptr;
    const char* streamName = nullptr;
    bool dumpraw = false;
    for (int i = 1; i < argc; i++) {
        if (i == 1) {
            cmd = argv[i];
        } else if (strcmp(argv[i], "-r") == 0) {
            dumpraw = true;
        } else {
            if (file == nullptr)
                file = argv[i];
            else
                streamName = argv[i];
        }
    }

    if (cmd == nullptr || file == nullptr) {
        ShowUsage();
        return 1;
    }

    FILE* fp = fopen(file, "rb");
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

    if (strcmp(cmd, "list") == 0) {
        ListDirectory(reader);
    } else if (strcmp(cmd, "dump") == 0 && streamName != nullptr) {
        const CFB::COMPOUND_FILE_ENTRY* entry = FindStream(reader, streamName, reader.GetRootEntry());
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
        else if (strcmp(streamName, "FileHeader") == 0)
            DumpHwpHeader(content.get(), size);
        else if (strcmp(streamName, "DocInfo") == 0) {
            DumpBuffer(content.get(), size);
            DumpDocInfo(content.get(), size);
        } else
            DumpBuffer(content.get(), size);
    } else if (strcmp(cmd, "info") == 0) {
        if (streamName == nullptr) {
            OutputFileInfo(reader);
        } else {
            const CFB::COMPOUND_FILE_ENTRY* entry = FindStream(reader, streamName, reader.GetRootEntry());
            if (entry == NULL) {
                cerr << "error: stream doesn't exist" << endl;
                return 2;
            }
            OutputEntryInfo(reader, entry);
        }
    } else {
        ShowUsage();
        return 1;
    }

    return 0;
}

int main(int argc, char* argv[]) {
    try {
        return main_internal(argc, argv);
    } catch (CFB::CFBException& e) {
        cerr << "error: " << e.what() << endl;
        return 2;
    }
}
