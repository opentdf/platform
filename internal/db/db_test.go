package db

// var (
// 	//nolint:gochecknoglobals // Test data and should be reintialized for each test
// 	resourceDescriptor = &common.ResourceDescriptor{
// 		Name:        "relto",
// 		Namespace:   "opentdf",
// 		Version:     1,
// 		Fqn:         "http://opentdf.com/attr/relto",
// 		Labels:      map[string]string{"origin": "Country of Origin"},
// 		Description: "The relto attribute is used to describe the relationship of the resource to the country of origin.",
// 		Type:        common.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_SYNONYM,
// 	}

// 	//nolint:gochecknoglobals // Test data and should be reintialized for each test
// 	testResource = &acre.Synonyms{
// 		Terms: []string{"relto", "rel-to", "rel_to"},
// 	}
// )

// func Test_RunMigrations_Returns_Expected_Applied(t *testing.T) {
// 	client := &Client{
// 		PgxIface: nil,
// 		config: Config{
// 			RunMigrations: false,
// 		},
// 	}

// 	applied, err := client.RunMigrations()

// 	assert.Nil(t, err)
// 	assert.Equal(t, 0, applied)
// }

// func Test_RunMigrations_Returns_Error_When_PGX_Iface_Is_Nil(t *testing.T) {
// 	client := &Client{
// 		PgxIface: nil,
// 		config: Config{
// 			RunMigrations: true,
// 		},
// 	}

// 	applied, err := client.RunMigrations()

// 	assert.ErrorContains(t, err, "failed to cast pgxpool.Pool")
// 	assert.Equal(t, 0, applied)
// }

// type BadPGX struct{}

// func (b BadPGX) Acquire(_ context.Context) (*pgxpool.Conn, error) { return &pgxpool.Conn{}, nil }
// func (b BadPGX) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
// 	return pgconn.CommandTag{}, nil
// }
// func (b BadPGX) QueryRow(context.Context, string, ...any) pgx.Row        { return nil }
// func (b BadPGX) Query(context.Context, string, ...any) (pgx.Rows, error) { return nil, nil }
// func (b BadPGX) Ping(context.Context) error                              { return nil }
// func (b BadPGX) Close()                                                  {}
// func (b BadPGX) Config() *pgxpool.Config                                 { return nil }

// func Test_RunMigrations_Returns_Error_When_PGX_Iface_Is_Wrong_Type(t *testing.T) {
// 	client := &Client{
// 		PgxIface: &BadPGX{},
// 		config: Config{
// 			RunMigrations: true,
// 		},
// 	}

// 	applied, err := client.RunMigrations()

// 	assert.ErrorContains(t, err, "failed to cast pgxpool.Pool")
// 	assert.Equal(t, 0, applied)
// }

// func Test_BuildURL_Returns_Expected_Connection_String(t *testing.T) {
// 	c := Config{
// 		Host:     "localhost",
// 		Port:     5432,
// 		Database: "opentdf",
// 		User:     "postgres",
// 		Password: "postgres",
// 		SSLMode:  "require",
// 	}

// 	url := c.buildURL()

// 	assert.Equal(t, "postgres://postgres:postgres@localhost:5432/opentdf?sslmode=require", url)
// }
