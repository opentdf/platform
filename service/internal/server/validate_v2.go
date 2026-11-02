package server

import (
	"context"
	"errors"

	"buf.build/go/protovalidate"
	connectv2 "connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connectproto"
	"google.golang.org/protobuf/proto"
)

// validateServerInterceptor validates every request message a connect-go v2
// handler receives against its protovalidate rules. Failures match the
// connectrpc.com/validate interceptor used for v1 handlers: InvalidArgument
// with the validation error as the message and the violations as a detail.
func validateServerInterceptor() connectv2.ServerInterceptor {
	return func(next connectv2.ServerFunc) connectv2.ServerFunc {
		return func(ctx context.Context, spec connectv2.Spec, stream connectv2.ServerStream) error {
			return next(ctx, spec, &validatingServerStream{ServerStream: stream})
		}
	}
}

type validatingServerStream struct {
	connectv2.ServerStream
}

func (s *validatingServerStream) Receive(msg any) error {
	if err := s.ServerStream.Receive(msg); err != nil {
		return err
	}
	return validateRequestMessage(msg)
}

func validateRequestMessage(msg any) error {
	protoMsg, ok := msg.(proto.Message)
	if !ok {
		return connectv2.Errorf(connectv2.CodeInternal, "expected proto.Message, got %T", msg)
	}
	err := protovalidate.GlobalValidator.Validate(protoMsg)
	if err == nil {
		return nil
	}
	connectErr := connectv2.NewError(connectv2.CodeInvalidArgument, err.Error()).WithCause(err)
	if validationErr := new(protovalidate.ValidationError); errors.As(err, &validationErr) {
		if detail, detailErr := connectproto.NewErrorDetail(validationErr.ToProto()); detailErr == nil {
			connectErr = connectErr.WithDetail(detail)
		}
	}
	return connectErr
}
