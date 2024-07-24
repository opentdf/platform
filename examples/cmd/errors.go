package cmd

type ExampleError string

func (e ExampleError) Error() string {
	return string(e)
}

const (
	ErrInvalidArgument ExampleError = "invalid parameter"
	ErrNotFound        ExampleError = "not found"
)
