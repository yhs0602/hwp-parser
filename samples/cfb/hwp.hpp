//
// Created by 양현서 on 12/15/23.
//

#ifndef HWP_HPP
#define HWP_HPP

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

# define HWPTAG_PARA_HEADER (HWPTAG_BEGIN+50) // 문단 헤더
# define HWPTAG_PARA_TEXT (HWPTAG_BEGIN+51) // 문단 텍스트
# define HWPTAG_PARA_CHAR_SHAPE (HWPTAG_BEGIN+52) // 문단 글자 모양
# define HWPTAG_PARA_LINE_SEG (HWPTAG_BEGIN+53) // 문단 줄 단위 정보
# define HWPTAG_PARA_RANGE_TAG (HWPTAG_BEGIN+54) // 문단 범위 태그
# define HWPTAG_CTRL_HEADER (HWPTAG_BEGIN+55) // 컨트롤 헤더
# define HWPTAG_LIST_HEADER (HWPTAG_BEGIN+56) // 리스트 헤더
# define HWPTAG_PAGE_DEF (HWPTAG_BEGIN+57) // 용지 정의
# define HWPTAG_FOOTNOTE_SHAPE (HWPTAG_BEGIN+58) // 각주/미주 모양
# define HWPTAG_PAGE_BORDER_FILL (HWPTAG_BEGIN+59) // 쪽 테두리/배경
# define HWPTAG_SHAPE_COMPONENT (HWPTAG_BEGIN+60) // 개체 구성요소
# define HWPTAG_TABLE (HWPTAG_BEGIN+61) // 표
# define HWPTAG_SHAPE_COMPONENT_LINE (HWPTAG_BEGIN+62) // 개체 구성요소 선
# define HWPTAG_SHAPE_COMPONENT_RECTANGLE (HWPTAG_BEGIN+63) // 개체 구성요소 사각형
# define HWPTAG_SHAPE_COMPONENT_ELLIPSE (HWPTAG_BEGIN+64) // 개체 구성요소 타원
# define HWPTAG_SHAPE_COMPONENT_ARC (HWPTAG_BEGIN+65) // 개체 구성요소 호
# define HWPTAG_SHAPE_COMPONENT_POLYGON (HWPTAG_BEGIN+66) // 개체 구성요소 다각형
# define HWPTAG_SHAPE_COMPONENT_CURVE (HWPTAG_BEGIN+67) // 개체 구성요소 곡선
# define HWPTAG_SHAPE_COMPONENT_OLE (HWPTAG_BEGIN+68) // 개체 구성요소 OLE
# define HWPTAG_SHAPE_COMPONENT_PICTURE (HWPTAG_BEGIN+69) // 개체 구성요소 그림
# define HWPTAG_SHAPE_COMPONENT_CONTAINER (HWPTAG_BEGIN+70) // 개체 구성요소 컨테이너
# define HWPTAG_CTRL_DATA (HWPTAG_BEGIN+71) // 컨트롤 데이터
# define HWPTAG_EQEDIT (HWPTAG_BEGIN+72) // 수식
# define RESERVED (HWPTAG_BEGIN+73) // 예약
# define HWPTAG_SHAPE_COMPONENT_TEXTART (HWPTAG_BEGIN+74) // 개체 구성요소 텍스트아트
# define HWPTAG_FORM_OBJECT (HWPTAG_BEGIN+75) // 양식 개체
// # define HWPTAG_MEMO_SHAPE (HWPTAG_BEGIN+76) // 메모 모양
# define HWPTAG_MEMO_LIST (HWPTAG_BEGIN+77) // 메모 리스트
# define HWPTAG_CHART_DATA (HWPTAG_BEGIN+79) // 차트 데이터
# define HWPTAG_VIDEO_DATA (HWPTAG_BEGIN+82) // 비디오 데이터
# define HWPTAG_SHAPE_COMPONENT_UNKNOWN (HWPTAG_BEGIN+99) // 개체 구성요소 알 수 없는 개체


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

struct hwptag_para_header {
    // 자료형
    // UINT32 4 text(=chars) if (nchars & 0x80000000) then nchars = nchars & 0x7FFFFFFF
    // UINT32 4 control mask
    // (UINT32)(1<<ctrlch) 조합
    // ctrlch는 HwpCtrlAPI.Hwp 2.1 CtrlCh 참고
    // UINT16 2 문단 모양 아이디 참조값
    // UINT8 1 문단 스타일 아이디 참조값
    // UINT8 1 단 나누기 종류(표 59 참조) 0x01 구역 나누기 0x02 다단 나누기 0x04 페이지 나누기 0x08 단 나누기
    // UINT16 2 글자 모양 정보 수
    // UINT16 2 range tag 정보 수
    // UINT16 2 각 줄에 대한 align에 대한 정보 수
    // UINT32 4 문단 Instance ID (unique ID)
    // UINT16 2 변경추적 병합 문단여부. (5.0.3.2 버전 이상)
    uint32_t text;
    uint32_t controlMask;
    uint16_t paragraphShapeID;
    uint8_t paragraphStyleID;
    uint8_t divideSort;
    uint16_t charShapeCount;
    uint16_t rangeTagCount;
    uint16_t alignCount;
    uint32_t instanceID;
    uint16_t trackChangeMerge;
};

struct hwptag_para_text {
    // WCHAR array[sizeof(nchars)]
    // 2×nchars 문자수만큼의 텍스트
    std::vector<uint16_t> text;
};

#pragma pack(pop)

using RecordVariant = std::variant<
    hwp_document_properties,
    hwptag_id_mappings,
    hwptag_bin_data,
    hwptag_para_header,
    hwptag_para_text
>;

// 레코드와 태그 ID를 함께 저장하는 래퍼 구조체
struct TaggedRecord {
    uint32_t tagID;
    uint32_t size;
    RecordVariant record;
};


#endif //HWP_HPP
