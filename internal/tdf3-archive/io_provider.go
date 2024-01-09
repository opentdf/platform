package tdf3_archiver

type IInputProvider interface {
	ReadBytes(int64, int64) ([]byte, error)
	GetSize() int64
}

type IOutputProvider interface {
	WriteBytes([]byte) error
}
