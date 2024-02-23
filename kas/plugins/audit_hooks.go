package main

import (
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/google/uuid"
)

const (
	AccessDeniedEvent EventType = "access_denied"
	DecryptEvent      EventType = "decrypt"
	TesTinEvent       EventType = "testint"
)

const (
	CreateTransaction      TransactionType = "create"
	CreateErrorTransaction TransactionType = "create_error"
)

const LogFileName = "logs.txt"

type a string

type Dissem struct {
	list []string
}

type AuditHookReturnValue struct {
	uuid   string
	dissem Dissem
}

type EventType string
type TransactionType string

type policyInfo struct{}
type symmetricAndPayloadConfig struct {
}
type Policy struct {
	uuid   string
	dissem []string
}

type TdfAttributes struct {
	dissem []string
	attrs  []string
}

type DataJson struct {
	policy    Policy
	keyAccess struct {
		header string
	}
}

type ActorAttributes struct {
	npe     bool
	actorId string
	attrs   []string
}

type AuditLog struct {
	id                   string
	transactionId        string
	transactionTimestamp string
	tdfId                string
	tdfName              string
	ownerId              string
	transactionType      TransactionType
	ownerOrganizationId  string
	eventType            EventType
	tdfAttributes        TdfAttributes
	actorAttributes      ActorAttributes
}

type eccMode struct {
}

func (receiver eccMode) parse(s string) (string, string) {
	return s, s
}

func (p Policy) constructFromRawCanonical(pl Policy) Policy {
	return pl
}

func (p policyInfo) parse(eccMode string, payloadConfig string, header string) (string, string) {
	return payloadConfig, header
}

func (p Policy) exportRaw() []string {
	return []string{}
}
func (p AuditHookReturnValue) exportRaw() []string {
	return []string{}
}

func (s1 symmetricAndPayloadConfig) parse(s string) (string, string) {
	return s, s
}

var OrgId = os.Getenv("CONFIG_ORG_ID")

var policy = Policy{uuid: uuid.NewString(), dissem: []string{""}}
var Middleware a
var PolicyInfo = policyInfo{}
var ECCMode = eccMode{}
var SymmetricAndPayloadConfig = symmetricAndPayloadConfig{}

func CreateLogger() (*slog.Logger, error) {
	logFile, err := os.OpenFile(LogFileName, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	// Make sure to close the file when you're done.
	// TODO Should we close file when server down ?
	// defer logFile.Close()

	logger := slog.New(slog.NewJSONHandler(logFile, nil))

	return logger, nil
}

func (g a) AuditHook(next http.Handler) http.Handler {
	logger, err := CreateLogger()
	if err != nil {
		panic(err)
	}
	auditHookLogger := logger.With("location", "AuditHook")
	auditHookLogger.Info("AuditHook call", "OrgId", OrgId)

	auditLog := AuditLog{
		id:                   uuid.NewString(),
		transactionId:        uuid.NewString(), // TODO
		transactionTimestamp: time.Now().Format(time.RFC3339Nano),
		tdfId:                policy.uuid,
		tdfName:              "",
		ownerId:              "",
		ownerOrganizationId:  OrgId,
		transactionType:      CreateTransaction,
		eventType:            DecryptEvent,
		tdfAttributes: TdfAttributes{
			dissem: []string{},
			attrs:  []string{},
		},
		actorAttributes: ActorAttributes{
			npe:     true,
			actorId: "",
			attrs:   []string{},
		},
	}

	auditLogAsString := fmt.Sprintf("%+v", auditLog)
	auditHookLogger.Info("Created AuditLog", "auditLog", auditLogAsString)

	auditLog.tdfAttributes.attrs = append(auditLog.tdfAttributes.attrs, policy.exportRaw()...)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auditHookLogger.Info("HTTP request", "Method", r.Method, "Url", r.URL.Path)

		auditLog.tdfAttributes.dissem = policy.dissem

		// TODO Use real token when /attribute endpoints will be ready
		// tokenString := r.Header.Get("Authorization")
		tokenString := `mock token`

		auditLog = ExtractInfoFromAuthToken(auditLog, tokenString)

		processedAuditLogAsString := fmt.Sprintf("%+v", auditLog)
		auditHookLogger.Info("Processed AuditLog", "auditLog", processedAuditLogAsString)

		next.ServeHTTP(w, r)
	})
}

func ErrAuditHook(err string) {
	log.SetPrefix("ErrAuditHook: ")
	log.Println("OrgId", OrgId)

	if err != "AuthorizationError" {
		log.Println("Access Denied with", err)
		log.Fatal("Access Denied")
	}

	auditLog := AuditLog{
		id:                   uuid.NewString(),
		transactionId:        uuid.NewString(), // TODO
		transactionTimestamp: time.Now().Format(time.RFC3339Nano),
		tdfId:                "",
		tdfName:              "",
		ownerId:              "",
		ownerOrganizationId:  OrgId,
		transactionType:      CreateErrorTransaction,
		eventType:            AccessDeniedEvent,
		tdfAttributes: TdfAttributes{
			dissem: []string{},
			attrs:  []string{},
		},
		actorAttributes: ActorAttributes{
			npe:     true,
			actorId: "",
			attrs:   []string{},
		},
	}

	// if "signedRequestToken" != data {
	//	 log.Println("Rewrap success without signedRequestToken - should never get here")
	//	 return
	// }
	// decoded_request = jwt.decode(
	//	data["signedRequestToken"],
	//	options={"verify_signature": False},
	//  algorithms=["RS256", "ES256", "ES384", "ES512"],
	//  leeway=30,
	// )
	// requestBody = decoded_request["requestBody"]
	// json_string = requestBody.replace("'", '"')
	// dataJson = json.loads(json_string)
	// dataJson := data
	// main.DataJson is missing fields policy, keyAccess (exhaustruct)
	// dataJson := DataJson{policy: Policy{uuid: "secp256r1"}}

	// if dataJson.policy.uuid == "ec:secp256r1" {
	//	// nano
	//	auditLog = ExtractPolicyDataFromNano(auditLog, dataJson, "", "")
	//	return
	// }
	// auditLog = ExtractPolicyDataFromTdf3(auditLog, dataJson)
	log.Println("AuditLog", auditLog)
}

func ExtractPolicyDataFromTdf3(auditLog AuditLog, dataJson DataJson) AuditLog {
	log.SetPrefix("ExtractPolicyDataFromTdf3: ")
	log.SetPrefix("ExtractPolicyDataFromTdf3: ")
	canonicalPolicy := dataJson.policy
	originalPolicy := policy.constructFromRawCanonical(canonicalPolicy)
	auditLog.tdfId = originalPolicy.uuid

	policy := AuditHookReturnValue{uuid: "mockUuid", dissem: Dissem{list: []string{""}}}

	log.Println("policy uuid", policy.uuid)

	auditLog.tdfAttributes.attrs = append(auditLog.tdfAttributes.attrs, policy.exportRaw()...)

	auditLog.tdfAttributes.dissem = policy.dissem.list
	return auditLog
}

func ExtractPolicyDataFromNano(auditLog AuditLog, dataJson DataJson, context string, keyMaster string) AuditLog {
	log.SetPrefix("ExtractPolicyDataFromNano: ")
	log.Println("context", context)
	log.Println("keyMaster", keyMaster)

	header := dataJson.keyAccess.header

	eccMode, header := ECCMode.parse(header)
	payloadConfig, header := SymmetricAndPayloadConfig.parse(header)

	_, _ = PolicyInfo.parse(eccMode, payloadConfig, header)

	//	private_key_bytes = key_master.get_key("KAS-EC-SECP256R1-PRIVATE").private_bytes(
	//		serialization.Encoding.DER,
	//		serialization.PrivateFormat.PKCS8,
	//		serialization.NoEncryption(),
	//	)
	//	decryptor = ecc_mode.curve.create_decryptor(
	//		header[0 : ecc_mode.curve.public_key_byte_length], private_key_bytes
	//	)
	//
	//	symmetric_cipher = payload_config.symmetric_cipher(
	//		decryptor.symmetric_key, b"\0" * (3 if legacy_wrapping else 12)
	//)
	//	policy_data = policy_info.body.data
	//
	//	policy_data_as_byte = base64.b64encode(
	//		symmetric_cipher.decrypt(
	//			policy_data[0 : len(policy_data) - payload_config.symmetric_tag_length],
	//			policy_data[-payload_config.symmetric_tag_length :],
	//		)
	//	)
	//	original_policy = Policy.construct_from_raw_canonical(
	//		policy_data_as_byte.decode("utf-8")
	//	)
	//

	policy := AuditHookReturnValue{uuid: "mockUuid", dissem: Dissem{list: []string{""}}}

	auditLog.tdfAttributes.attrs = append(auditLog.tdfAttributes.attrs, policy.exportRaw()...)
	auditLog.tdfAttributes.dissem = policy.dissem.list

	return auditLog
}

func ExtractInfoFromAuthToken(auditLog AuditLog, token string) AuditLog {
	log.SetPrefix("ExtractInfoFromAuthToken: ")

	// secret := []byte("itsa16bytesecret")
	// tok, err := jwt.ParseEncrypted(tokenString)
	//
	// if err != nil {
	//	 log.Fatal(err)
	// }
	//
	// decodedToken := jwt.Claims{}
	// if err := tok.Claims(secret, &decodedToken); err != nil {
	// 	log.Fatal(err)
	// }
	// log.Println(decodedToken)
	// auditLog.ownerId = decodedToken.Subject

	// if decoded_auth.get("tdf_claims").get("entitlements"):
	//	 attributes = set()
	//	 # just put all entitlements into one list, dont seperate by entity for now
	//	 for item in decoded_auth.get("tdf_claims").get("entitlements"):
	//		for attribute in item.get("entity_attributes"):
	//			attributes.add(attribute.get("attribute"))
	//	audit_log["actorAttributes"]["attrs"] = list(attributes)
	//	if decoded_auth.get("azp"):
	//		audit_log["actorAttributes"]["actorId"] = decoded_auth.get("azp")

	return auditLog
}
