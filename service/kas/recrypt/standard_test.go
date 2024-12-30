package recrypt

import (
	"github.com/stretchr/testify/suite"
)

type StandardTestSuite struct {
	suite.Suite
	*Standard
}

func (suite *StandardTestSuite) SetupSuite() {
	suite.Standard = NewStandard()
}

