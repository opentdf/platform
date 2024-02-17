package archive

const (
	fileHeaderSignature             = 0x04034b50 // (PK♥♦ or "PK\3\4")
	dataDescriptorSignature         = 0x08074b50
	centralDirectoryHeaderSignature = 0x02014b50
	endOfCentralDirectorySignature  = 0x06054b50
	zip64EndOfCDLocatorSignature    = 0x07064b50
	zip64MagicVal                   = 0xFFFFFFFF
	zip64EndOfCDSignature           = 0x06064b50
	zip64ExternalID                 = 0x0001
	zipVersion                      = 0x2D // version 4.5 of the PKZIP specification
)

const (
	endOfCDRecordSize                    = 22
	zip64EndOfCDRecordLocatorSize        = 20
	zip64EndOfCDRecordSize               = 56
	cdFileHeaderSize                     = 46
	localFileHeaderSize                  = 30
	zip64ExtendedLocalInfoExtraFieldSize = 20
	zip64DataDescriptorSize              = 24
	zip32DataDescriptorSize              = 16
	zip64ExtendedInfoExtraFieldSize      = 28
)

type LocalFileHeader struct {
	Signature             uint32
	Version               uint16
	GeneralPurposeBitFlag uint16
	CompressionMethod     uint16
	LastModifiedTime      uint16
	LastModifiedDate      uint16
	Crc32                 uint32
	CompressedSize        uint32
	UncompressedSize      uint32
	FilenameLength        uint16
	ExtraFieldLength      uint16
}

type Zip32DataDescriptor struct {
	Signature        uint32
	Crc32            uint32
	CompressedSize   uint32
	UncompressedSize uint32
}

type Zip64DataDescriptor struct {
	Signature        uint32
	Crc32            uint32
	CompressedSize   uint64
	UncompressedSize uint64
}

type CDFileHeader struct {
	Signature              uint32
	VersionCreated         uint16
	VersionNeeded          uint16
	GeneralPurposeBitFlag  uint16
	CompressionMethod      uint16
	LastModifiedTime       uint16
	LastModifiedDate       uint16
	Crc32                  uint32
	CompressedSize         uint32
	UncompressedSize       uint32
	FilenameLength         uint16
	ExtraFieldLength       uint16
	FileCommentLength      uint16
	DiskNumberStart        uint16
	InternalFileAttributes uint16
	ExternalFileAttributes uint32
	LocalHeaderOffset      uint32
}

type EndOfCDRecord struct {
	Signature               uint32
	DiskNumber              uint16
	StartDiskNumber         uint16
	NumberOfCDRecordEntries uint16
	TotalCDRecordEntries    uint16
	SizeOfCentralDirectory  uint32
	CentralDirectoryOffset  uint32
	CommentLength           uint16
}

type Zip64EndOfCDRecord struct {
	Signature                          uint32
	RecordSize                         uint64
	VersionMadeBy                      uint16
	VersionToExtract                   uint16
	DiskNumber                         uint32
	StartDiskNumber                    uint32
	NumberOfCDRecordEntries            uint64
	TotalCDRecordEntries               uint64
	CentralDirectorySize               uint64
	StartingDiskCentralDirectoryOffset uint64
}

type Zip64EndOfCDRecordLocator struct {
	Signature         uint32
	CDStartDiskNumber uint32
	CDOffset          uint64
	NumberOfDisks     uint32
}

type Zip64ExtendedLocalInfoExtraField struct {
	Signature      uint16
	Size           uint16
	OriginalSize   uint64
	CompressedSize uint64
}

type Zip64ExtendedInfoExtraField struct {
	Signature             uint16
	Size                  uint16
	OriginalSize          uint64
	CompressedSize        uint64
	LocalFileHeaderOffset uint64
}
