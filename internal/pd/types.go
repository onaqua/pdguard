// Package pd defines the catalog of personal data categories and the span
// type produced by detectors and consumed by the masking engine.
package pd

// Type is a personal data category. Values are stable wire identifiers: they
// appear in configs, logs, and metrics, so renaming requires a migration note.
type Type string

const (
	TypeFIO               Type = "FIO"                 // Фамилия Имя Отчество
	TypeBirthDate         Type = "BIRTH_DATE"          // Дата рождения
	TypeBirthPlace        Type = "BIRTH_PLACE"         // Место рождения
	TypePassport          Type = "PASSPORT"            // Паспорт РФ
	TypePassportIssueDate Type = "PASSPORT_ISSUE_DATE" // Дата выдачи паспорта
	TypePassportIssuer    Type = "PASSPORT_ISSUER"     // Кем выдан паспорт
	TypeSubdivisionCode   Type = "SUBDIVISION_CODE"    // Код подразделения
	TypeCitizenship       Type = "CITIZENSHIP"         // Гражданство
	TypeDriverLicense     Type = "DRIVER_LICENSE"      // Водительское удостоверение
	TypeAddress           Type = "ADDRESS"             // Адрес
	TypeCountry           Type = "COUNTRY"             // Страна
	TypePostalCode        Type = "POSTAL_CODE"         // Почтовый индекс
	TypeCity              Type = "CITY"                // Город
	TypeStreet            Type = "STREET"              // Улица
	TypeHouse             Type = "HOUSE"               // Дом
	TypeApartment         Type = "APARTMENT"           // Квартира
	TypeEmail             Type = "EMAIL"               // Электронная почта
	TypePhone             Type = "PHONE"               // Телефон
	TypeINN               Type = "INN"                 // ИНН
	TypeCardNumber        Type = "CARD_NUMBER"         // Номер банковской карты
	TypeCardHolder        Type = "CARD_HOLDER"         // Держатель карты
	TypeCVV               Type = "CVV"                 // CVV-код карты
	TypePIN               Type = "PIN"                 // PIN-код
	TypeSNILS             Type = "SNILS"               // СНИЛС
	TypeForeignPassport   Type = "FOREIGN_PASSPORT"    // Загранпаспорт
	TypeBirthCertificate  Type = "BIRTH_CERTIFICATE"   // Свидетельство о рождении
	TypeMilitaryID        Type = "MILITARY_ID"         // Военный билет
	TypeResidencePermit   Type = "RESIDENCE_PERMIT"    // Вид на жительство
	TypeOMS               Type = "OMS_POLICY"          // Полис ОМС
	TypeBankAccount       Type = "BANK_ACCOUNT"        // Банковский счёт
)

// AllTypes is the canonical order used for configuration and documentation
// generation.
var AllTypes = []Type{
	TypeFIO,
	TypeBirthDate,
	TypeBirthPlace,
	TypePassport,
	TypePassportIssueDate,
	TypePassportIssuer,
	TypeSubdivisionCode,
	TypeCitizenship,
	TypeDriverLicense,
	TypeAddress,
	TypeCountry,
	TypePostalCode,
	TypeCity,
	TypeStreet,
	TypeHouse,
	TypeApartment,
	TypeEmail,
	TypePhone,
	TypeINN,
	TypeCardNumber,
	TypeCardHolder,
	TypeCVV,
	TypePIN,
	TypeSNILS,
	TypeForeignPassport,
	TypeBirthCertificate,
	TypeMilitaryID,
	TypeResidencePermit,
	TypeOMS,
	TypeBankAccount,
}

// Priority decides which detection survives when spans overlap: a higher
// value wins. Long, unambiguous identifiers outrank short numeric ones,
// because a CVV pattern inside a card number must not split the card.
func (t Type) Priority() int {
	switch t {
	case TypeCardNumber, TypeBankAccount:
		return 100
	case TypeSNILS, TypeINN:
		return 95
	case TypePassport, TypeForeignPassport, TypeDriverLicense, TypeOMS:
		return 90
	case TypeEmail:
		return 88
	case TypePhone:
		return 85
	case TypeAddress:
		return 80
	case TypeFIO, TypeCardHolder:
		return 75
	case TypeBirthDate, TypePassportIssueDate:
		return 70
	case TypePassportIssuer, TypeBirthPlace:
		return 65
	case TypeSubdivisionCode, TypeMilitaryID, TypeBirthCertificate, TypeResidencePermit:
		return 60
	case TypeCitizenship:
		return 55
	case TypeCity, TypeStreet, TypeHouse, TypeApartment, TypePostalCode, TypeCountry:
		return 50
	case TypeCVV, TypePIN:
		return 40
	default:
		return 10
	}
}

// Span is a half-open byte range [Start, End) over the original text. Byte
// offsets (not runes) are used so that slices are O(1).
type Span struct {
	Start int     `json:"start"`
	End   int     `json:"end"`
	Type  Type    `json:"type"`
	Conf  float64 `json:"conf"`           // 0..1 detector confidence
	Src   string  `json:"src"`            // detector name, for logs and debugging
	Hint  string  `json:"hint,omitempty"` // optional subform, e.g. "surname", "series"
}

// Len returns the length of the span in bytes.
func (s Span) Len() int { return s.End - s.Start }

// Overlaps reports whether two spans share at least one byte.
func (s Span) Overlaps(o Span) bool { return s.Start < o.End && o.Start < s.End }
