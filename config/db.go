package config

import (

	// "database/sql"
	// "net/http"
	// "github.com/vault/api"

	"database/sql"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	"github.com/hashicorp/vault/api"
	_ "github.com/lib/pq"

	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/hashicorp/vault/api"
)

//DBuser holds DB user info
type DBuser struct {
	Username string
	Password string
}

//DB Connection
var DB *sql.DB
var AppDBuser DBuser
var httpClient = &http.Client{
	Timeout: 10 * time.Second,
}

//Vclient holds our HashiCorp Vault Client
var Vclient, _ = api.NewClient(&api.Config{Address: "http://vault-ui.default.svc:8200", HttpClient: httpClient})
var tokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"
var K8sAuthRole = "vault_go_demo"
var K8sAuthPath = "auth/kubernetes/login"
var AWSAuthRole = "auth/aws/login"

func init() {
	fmt.Printf("Vault client init....\n")

	AWSLogin("aws", "", "my-role-iam")

	Vclient.SetToken(secret.Auth.ClientToken)

	//Pull dynamic database credentials
	data, err := Vclient.Logical().Read("database/creds/vault_go_demo")
	if err != nil {
		log.Fatal(err)
	}
	username := data.Data["username"]
	password := data.Data["password"]
	SQLQuery := "postgres://" + username.(string) + ":" + password.(string) + "@pq-postgresql-headless.default.svc:5432/vault_go_demo?sslmode=disable"

	AppDBuser.Username = username.(string)
	AppDBuser.Password = password.(string)

	//Don't do this in production!
	fmt.Printf("\nDB Username: %v\n", AppDBuser.Username)
	fmt.Printf("DB Password: %v\n\n", AppDBuser.Password)

	//DB setup
	DB, err = sql.Open("postgres", SQLQuery)
	if err != nil {
		log.Fatal(err)
	}
	if err = DB.Ping(); err != nil {
		panic(err)
	}
	fmt.Println("Connected to database\n")

	SQLQuery = "DROP TABLE vault_go_demo;"
	DB.Exec(SQLQuery)
	SQLQuery = "CREATE TABLE vault_go_demo (CUST_NO SERIAL PRIMARY KEY, FIRST TEXT NOT NULL, LAST TEXT NOT NULL, SSN TEXT NOT NULL, ADDR CHAR(50), BDAY DATE DEFAULT '1900-01-01', SALARY REAL DEFAULT 25500.00);"
	DB.Exec(SQLQuery)
	SQLQuery = "INSERT INTO vault_go_demo (FIRST, LAST, SSN, ADDR, BDAY, SALARY) VALUES('John', 'Doe', '435-59-5123', '456 Main Street', '1980-01-01', 60000.00);"
	DB.Exec(SQLQuery)
	SQLQuery = "INSERT INTO vault_go_demo (FIRST, LAST, SSN, ADDR, BDAY, SALARY) VALUES('Jane', 'Smith', '765-24-2083', '331 Johnson Street', '1985-02-02', 120000.00);"
	DB.Exec(SQLQuery)
	SQLQuery = "INSERT INTO vault_go_demo (FIRST, LAST, SSN, ADDR, BDAY, SALARY) VALUES('Ben', 'Franklin', '111-22-8084', '222 Chicago Street', '1985-02-02', 180000.00);"
	DB.Exec(SQLQuery)

}

func AWSLogin(authProvider, serverID, role string) (client *api.Client, token string, secret *api.Secret, err error) {

	// Create the Vault client.
	//
	// Configuration is gathered from environment variables by upstream vault package. Environment variables like
	// VAULT_ADDR and VAULT_SKIP_VERIFY are relevant. The VAULT_TOKEN environment variable shouldn't be needed.
	// https://www.vaultproject.io/docs/commands#environment-variables
	if client, err = api.NewClient(nil); err != nil {
		return nil, "", nil, fmt.Errorf("failed to create Vault client: %w", err)
	}

	// Acquire an AWS session.
	var sess *session.Session
	if sess, err = session.NewSession(); err != nil {
		return nil, "", nil, fmt.Errorf("failed to create AWS session: %w", err)
	}

	// Create a Go structure to talk to the AWS token service.
	tokenService := sts.New(sess)

	// Create a request to the token service that will ask for the current host's identity.
	request, _ := tokenService.GetCallerIdentityRequest(&sts.GetCallerIdentityInput{})

	// Add an server ID IAM header, if present.
	if serverID != "" {
		request.HTTPRequest.Header.Add("X-Vault-AWS-IAM-Server-ID", serverID)
	}

	// Sign the request to the AWS token service.
	if err = request.Sign(); err != nil {
		return nil, "", nil, fmt.Errorf("failed to sign AWS identity request: %w", err)
	}

	// JSON marshal the headers.
	var headers []byte
	if headers, err = json.Marshal(request.HTTPRequest.Header); err != nil {
		return nil, "", nil, fmt.Errorf("failed to JSON marshal HTTP headers for AWS identity request: %w", err)
	}

	// Read the body of the request.
	var body []byte
	if body, err = ioutil.ReadAll(request.HTTPRequest.Body); err != nil {
		return nil, "", nil, fmt.Errorf("failed to JSON marshal HTTP body for AWS identity request: %w", err)
	}

	// Create the data to write to Vault.
	data := make(map[string]interface{})
	data["iam_http_request_method"] = request.HTTPRequest.Method
	data["iam_request_url"] = base64.StdEncoding.EncodeToString([]byte(request.HTTPRequest.URL.String()))
	data["iam_request_headers"] = base64.StdEncoding.EncodeToString(headers)
	data["iam_request_body"] = base64.StdEncoding.EncodeToString(body)
	data["role"] = role

	path := fmt.Sprintf("auth/%s/login", authProvider)

	// Write the AWS token service request to Vault.
	if secret, err = client.Logical().Write(path, data); err != nil {
		return nil, "", nil, fmt.Errorf("failed to write data to Vault to get token: %w", err)
	}
	if secret == nil {
		return nil, "", nil, fmt.Errorf("failed to get token from Vault: %w", ErrSecret)
	}

	// Get the Vault token from the response.
	if token, err = secret.TokenID(); err != nil {
		return nil, "", nil, fmt.Errorf("failed to get token from Vault response: %w", err)
	}

	// Set the token for the client as the one it just received.
	client.SetToken(token)

	return client, token, secret, nil
}

// Create Table vault-go-demo (
// 	CUST_NO SERIAL PRIMARY KEY,
// 	FIRST               TEXT NOT NULL,
// 	LAST                TEXT NOT NULL,
// 	SSN                 TEXT NOT NULL,
// 	ADDR                CHAR(50),
// 	BDAY			    DATE DEFAULT '1900-01-01',
// 	SALARY              REAL DEFAULT 25500.00
// );
