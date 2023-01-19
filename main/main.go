package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/aws/aws-sdk-go/service/sts"
)

var (
	//apiKey     = kmsDecrypt(os.Getenv("apikey"))
	apiKey       = os.Getenv("apikey2")
	profile      = "PROFILE"
	pdScheduleId = os.Getenv("pd_schedule_id")
	pagerDutyURL = "https://api.pagerduty.com/oncalls"
	oncall       string
	roleArn      = "<IAM_ROLE_ARN>"
)

type Response struct {
	Oncalls []struct {
		EscalationPolicy struct {
			ID      string `json:"id"`
			Type    string `json:"type"`
			Summary string `json:"summary"`
			Self    string `json:"self"`
			HTMLURL string `json:"html_url"`
		} `json:"escalation_policy"`
		EscalationLevel int         `json:"escalation_level"`
		Schedule        interface{} `json:"schedule"`
		User            struct {
			ID      string `json:"id"`
			Type    string `json:"type"`
			Summary string `json:"summary"`
			Self    string `json:"self"`
			HTMLURL string `json:"html_url"`
		} `json:"user"`
		Start interface{} `json:"start"`
		End   interface{} `json:"end"`
	} `json:"oncalls"`
	Limit  int         `json:"limit"`
	Offset int         `json:"offset"`
	More   bool        `json:"more"`
	Total  interface{} `json:"total"`
}

func kmsDecrypt(encryptedText string) string {
	sess := session.Must(session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	}))

	stsClient := sts.New(sess)

	assumeRoleInput := &sts.AssumeRoleInput{
		RoleArn:         aws.String(roleArn),
		RoleSessionName: aws.String("raven1"),
	}
	assumeRoleOutput, _ := stsClient.AssumeRole(assumeRoleInput)

	tempCreds := credentials.NewStaticCredentials(
		*assumeRoleOutput.Credentials.AccessKeyId,
		*assumeRoleOutput.Credentials.SecretAccessKey,
		*assumeRoleOutput.Credentials.SessionToken)

	tempSession := session.Must(session.NewSession(&aws.Config{
		Credentials: tempCreds,
	}))

	// Create a new KMS client
	kmsClient := kms.New(tempSession)

	data, _ := base64.StdEncoding.DecodeString(encryptedText)
	ciphertext := []byte(data)

	// Call the Decrypt API
	result, _ := kmsClient.Decrypt(&kms.DecryptInput{
		CiphertextBlob: ciphertext,
	})

	return string(result.Plaintext)

}

func handler(request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {

	req, err := http.NewRequest("GET", pagerDutyURL, nil)
	if err != nil {
		panic(err)
	}

	req.Header.Add("Accept", "application/vnd.pagerduty+json;version=2")
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", "Token token="+apiKey)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	jsonDataFromHttp, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		panic(err)
	}

	var response = new(Response)

	err = json.Unmarshal(jsonDataFromHttp, &response)

	if err != nil {
		panic(err)
	}
	oncall = ""
	for _, r := range response.Oncalls {
		if r.EscalationPolicy.ID == pdScheduleId {
			name := strings.Split(r.User.Summary, " ")
			oncall += fmt.Sprintf("*Level %v* - %v is oncall until %v\n", r.EscalationLevel, name[0], r.End)
		}

	}

	return events.APIGatewayProxyResponse{
		Body:       oncall,
		StatusCode: 200,
	}, nil

}

func main() {
	lambda.Start(handler)
}
