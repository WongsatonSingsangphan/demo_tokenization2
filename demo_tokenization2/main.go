package main

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"net/smtp"
	"strings"
	"time"

	"demo_tokenization_prod/database"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

var user struct {
	Username string `json:"username"`
	// Password        string `json:"password"`
	// Newpassword     string `json:"newpassword"`
	Firstname       string `json:"firstname"`
	Surname         string `json:"surname"`
	Firstname_en    string `json:"firstname_en"`
	Surname_en      string `json:"surname_en"`
	Mobile_phone    string `json:"mobile_phone"`
	Personal_email  string `json:"personal_email"`
	Company_name    string `json:"company_name"`
	Company_name_en string `json:"company_name_en"`
	// Requiresaction  string `json:"requires_action"`
	Credit_card string `json:"credit_card"`
	Role        string `json:"role"`
	Country     string `json:"country"`
	Province    string `json:"province"`
	Amphoe      string `json:"amphoe"`
	Tambon      string `json:"tambon"`
	Zipcode     string `json:"zipcode"`
	Website     string `json:"website"`
	Address1    string `json:"address1"`
	Address2    string `json:"address2"`
	Title       string `json:"title"`
}

type CustomClaims struct {
	ID                string `json:"id"`
	Username          string `json:"username"`
	UsernameOriginal  string `JSON:"username_original"`
	UsernameToken     string `json:"username_token"`
	PasswordHash      string `json:"password_hash"`
	FirstnameOriginal string `json:"firstname_original"`
	FirstnameToken    string `json:"firstname_token"`
	SurnameOriginal   string `json:"surname_origianl"`
	SurnameToken      string `json:"surname_token"`
	CompanyOriginal   string `json:"company_name"`
	CompanyToken      string `json:"company_token"`
	// PersonalEmail string `json:"personal_email"`
	Timestamp       string `json:"timestamp"`
	Requires_action string `json:"requires_action"`
	// CreditCardToken    string `json:"credit_card_token"`
	CreditCardOriginal string `json:"credit_card_original"`
	CreditCardMasked   string `json:"credit_card_masked"`
	Role               string `json:"role"`
	Exp                int64  `json:"exp"`
}

const (
	keyUsername = "e230944a-e25d-4674-83c7-436f7085086e"
	keyPassword = "LLodeHVjIDV-N13thflXkjWZuu1y4rCo723BGOLQ8RYGAalYETJz5HmsYx5MXwfH3mgTXw93UxtzVfPgzGNYCw"
)

func main() {
	db := database.Postgresql()
	defer db.Close()

	r := gin.Default()
	config := cors.DefaultConfig()
	config.AllowOrigins = []string{"*"}
	config.AllowMethods = []string{"GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"}
	config.AllowHeaders = []string{"Origin", "Content-Type", "X-Auth-Token", "Authorization"}

	r.Use(cors.New(config))

	r.GET("/api/decryptthai", func(c *gin.Context) {
		var decryptthai struct {
			ID string
			// Username  string
			Firstname string
			Surname   string
		}

		// รับค่า id จากคำขอ
		id := c.Query("id") // คาดว่าคุณจะใช้ Query Parameter

		err := db.QueryRow("SELECT id, firstname, surname FROM user_credential_V2 WHERE id = $1", id).Scan(&decryptthai.ID, &decryptthai.Firstname, &decryptthai.Surname)

		if err == sql.ErrNoRows {
			c.JSON(http.StatusUnauthorized, gin.H{"status": "Error", "message": "User not found"})
			return
		} else if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"status": "Error", "message": err.Error()})
			return
		}

		// เรียกใช้ Decryptthai เพื่อถอดรหัสข้อมูล firstname
		decryptedFirstname, err := Decryptthai(decryptthai.Firstname)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"status": "Error", "message": err.Error()})
			return
		}
		decryptedSurname, err := Decryptthai((decryptthai.Surname))
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"status": "Error", "message": err.Error()})
			return
		}
		// ส่งค่าที่ถอดรหัสแล้วกลับไป
		c.JSON(http.StatusOK, gin.H{
			"ID": decryptthai.ID,
			// "Username":  decryptthai.Username,
			"Firstname": decryptedFirstname, // ใช้ค่าที่ถอดรหัสแล้ว
			"Surname":   decryptedSurname,
			"status":    "OK",
			"message":   "Succesfully",
		})
	})

	r.DELETE("/api/delete-user-by-id", func(c *gin.Context) {
		var deleteRequest struct {
			ID string `json:"id" binding:"required"`
		}

		// ดึงข้อมูลจาก JSON body
		if err := c.ShouldBindJSON(&deleteRequest); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"status": "Error", "message": "Invalid request", "details": err.Error()})
			return
		}

		// ตรวจสอบว่า ID ถูกส่งมาหรือไม่
		if deleteRequest.ID == "" {
			c.JSON(http.StatusBadRequest, gin.H{"status": "Error", "message": "ID is required"})
			return
		}

		// ทำการลบข้อมูลจากฐานข้อมูล
		_, err := db.Exec("DELETE FROM user_credential_V2 WHERE id = $1", deleteRequest.ID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"status": "Error", "message": err.Error()})
			return
		}

		// ส่ง response กลับเมื่อการลบสำเร็จ
		c.JSON(http.StatusOK, gin.H{"status": "OK", "message": "User deleted successfully"})
	})

	// r.GET("/users", func(c *gin.Context) {
	// 	// ดึงข้อมูลทั้งหมดจากฐานข้อมูล
	// 	rows, err := db.Query("SELECT id, username, firstname, surname, mobile_phone, personal_email, company_name FROM user_credential_V2")
	// 	if err != nil {
	// 		c.JSON(http.StatusInternalServerError, gin.H{"status": "Error", "message": err.Error()})
	// 		return
	// 	}
	// 	defer rows.Close()

	// 	var users []struct {
	// 		ID            string
	// 		Username      string
	// 		Firstname     string
	// 		Surname       string
	// 		MobilePhone   string
	// 		PersonalEmail string
	// 		CompanyName   string
	// 	}

	// 	for rows.Next() {
	// 		var user struct {
	// 			ID            string
	// 			Username      string
	// 			Firstname     string
	// 			Surname       string
	// 			MobilePhone   string
	// 			PersonalEmail string
	// 			CompanyName   string
	// 		}

	// 		err := rows.Scan(&user.ID, &user.Username, &user.Firstname, &user.Surname, &user.MobilePhone, &user.PersonalEmail, &user.CompanyName)
	// 		if err != nil {
	// 			c.JSON(http.StatusInternalServerError, gin.H{"status": "Error", "message": err.Error()})
	// 			return
	// 		}

	// 		users = append(users, user)
	// 	}

	// 	c.JSON(http.StatusOK, users)
	// })

	r.GET("/api/users", AdminOnly(), func(c *gin.Context) {
		// ดึงข้อมูลทั้งหมดจากฐานข้อมูล
		rows, err := db.Query("SELECT id, username, username_token, firstname_en, surname_en, mobile_phone, personal_email, company_name, role FROM user_credential_V2")
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"status": "Error", "message": err.Error()})
			return
		}
		defer rows.Close()

		var users []struct {
			ID                string
			Username          string
			UsernameOriginal  string
			Firstname         string
			FirstnameOriginal string
			Surname           string
			SurnameOriginal   string
			MobilePhone       string
			PersonalEmail     string
			CompanyName       string
			Role              string
		}

		for rows.Next() {
			var user struct {
				ID                string
				Username          string
				UsernameToken     string
				Firstname         string // en
				FirstnameOriginal string
				Surname           string // en
				SurnameOriginal   string
				MobilePhone       string
				PersonalEmail     string
				CompanyName       string
				Role              string
			}

			err := rows.Scan(&user.ID, &user.Username, &user.UsernameToken, &user.Firstname, &user.Surname, &user.MobilePhone, &user.PersonalEmail, &user.CompanyName, &user.Role)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"status": "Error", "message": err.Error()})
				return
			}

			var (
				// decodedUsername             []byte
				// decodedCreditcard           []byte
				// decodedCreditcardTokenBytes []byte
				// decodedUsernameToken        []byte
				decodedUsernameTokenBytes  []byte
				decodedFirstnameTokenBytes []byte
				// decodedSurnameToken        []byte
				decodedSurnameTokenBytes []byte
				// decodedCompanyToken      []byte
				// decodedCompanyTokenBytes []byte
				errChan = make(chan error, 3)
			)

			// Detokenize username_token
			go func() {
				var err error
				decodedUsernameToken, err := detokenizeMaskToken(user.UsernameToken)
				if err != nil {
					errChan <- err
					return
				}
				decodedUsernameTokenBytes, err = base64.StdEncoding.DecodeString(decodedUsernameToken)
				errChan <- err
			}()

			go func() {
				var err error
				decodedFirstnameToken, err := detokenize(user.Firstname)
				if err != nil {
					errChan <- err
					return
				}
				decodedFirstnameTokenBytes, err = base64.StdEncoding.DecodeString(string(decodedFirstnameToken))
				errChan <- err
			}()

			go func() {
				var err error
				decodedSurnameToken, err := detokenize(user.Surname)
				if err != nil {
					errChan <- err
					return
				}
				decodedSurnameTokenBytes, err = base64.StdEncoding.DecodeString(string(decodedSurnameToken))
				errChan <- err
			}()

			for i := 0; i < 3; i++ {
				if err := <-errChan; err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"status": "Error", "message": err.Error()})
					return
				}
			}

			users = append(users, struct {
				ID                string
				Username          string
				UsernameOriginal  string
				Firstname         string
				FirstnameOriginal string
				Surname           string
				SurnameOriginal   string
				MobilePhone       string
				PersonalEmail     string
				CompanyName       string
				Role              string
			}{
				ID:                user.ID,
				Username:          user.Username,
				UsernameOriginal:  string(decodedUsernameTokenBytes),
				Firstname:         user.Firstname,
				FirstnameOriginal: string(decodedFirstnameTokenBytes),
				Surname:           user.Surname,
				SurnameOriginal:   string(decodedSurnameTokenBytes),
				MobilePhone:       user.MobilePhone,
				PersonalEmail:     user.PersonalEmail,
				CompanyName:       user.CompanyName,
				Role:              user.Role,
			})
		}

		c.JSON(http.StatusOK, users)
	})

	// r.GET("/users", AdminOnly(), func(c *gin.Context) { <<<<<<<<<<< loop v2
	// 	// ดึงข้อมูลทั้งหมดจากฐานข้อมูล
	// 	rows, err := db.Query("SELECT id, username, username_token, firstname, surname, mobile_phone, personal_email, company_name FROM user_credential_V2")
	// 	if err != nil {
	// 		c.JSON(http.StatusInternalServerError, gin.H{"status": "Error", "message": err.Error()})
	// 		return
	// 	}
	// 	defer rows.Close()

	// 	type User struct {
	// 		ID            string
	// 		Username      string
	// 		UsernameToken string
	// 		Firstname     string
	// 		Surname       string
	// 		MobilePhone   string
	// 		PersonalEmail string
	// 		CompanyName   string
	// 	}

	// 	var users []User
	// 	var usernameTokens []string

	// 	for rows.Next() {
	// 		var user User
	// 		err := rows.Scan(&user.ID, &user.Username, &user.UsernameToken, &user.Firstname, &user.Surname, &user.MobilePhone, &user.PersonalEmail, &user.CompanyName)
	// 		if err != nil {
	// 			c.JSON(http.StatusInternalServerError, gin.H{"status": "Error", "message": err.Error()})
	// 			return
	// 		}
	// 		users = append(users, user)
	// 		usernameTokens = append(usernameTokens, user.UsernameToken)
	// 	}

	// 	// Detokenize หลังจาก loop
	// 	for i, token := range usernameTokens {
	// 		decodedUsernameToken, err := detokenizeMaskToken(token)
	// 		if err != nil {
	// 			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
	// 			return
	// 		}
	// 		decodedUsernameTokenBytes, err := base64.StdEncoding.DecodeString(decodedUsernameToken)
	// 		if err != nil {
	// 			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
	// 			return
	// 		}
	// 		users[i].Username = string(decodedUsernameTokenBytes)
	// 	}

	// 	// ส่ง response
	// 	c.JSON(http.StatusOK, users)
	// })

	// r.GET("/userlog", func(c *gin.Context) {
	r.GET("/api/userlog", AdminOnly(), func(c *gin.Context) {
		rows, err := db.Query(`
			SELECT 
				user_id,
				action_type,
				action_timestamp,
				COALESCE(previous_data::jsonb, '{}') AS previous_data,
				COALESCE(new_data::jsonb, '{}') AS new_data
			FROM public.user_credential_v2_log
		`)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"status": "Error", "message": err.Error()})
			return
		}
		defer rows.Close()

		var userLogs []struct {
			UserID          string          `json:"user_id"`
			ActionType      string          `json:"action_type"`
			ActionTimestamp string          `json:"action_timestamp"`
			PreviousData    json.RawMessage `json:"previous_data"`
			NewData         json.RawMessage `json:"new_data"`
		}

		for rows.Next() {
			var userLog struct {
				UserID          string          `json:"user_id"`
				ActionType      string          `json:"action_type"`
				ActionTimestamp string          `json:"action_timestamp"`
				PreviousData    json.RawMessage `json:"previous_data"`
				NewData         json.RawMessage `json:"new_data"`
			}

			err := rows.Scan(
				&userLog.UserID,
				&userLog.ActionType,
				&userLog.ActionTimestamp,
				&userLog.PreviousData,
				&userLog.NewData,
			)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"status": "Error", "message": err.Error()})
				return
			}

			userLogs = append(userLogs, userLog)
		}

		c.JSON(http.StatusOK, userLogs)
	})

	r.GET("/api/userlog-sudo", func(c *gin.Context) {

		config := cors.DefaultConfig()
		config.AllowOrigins = []string{"http://localhost:3001"}
		config.AllowCredentials = true
		config.AllowHeaders = []string{"Authorization"} // ระบุ "Authorization" เท่านั้น
		cors.New(config)

		rows, err := db.Query(`
			SELECT 
				user_id,
				action_type,
				action_timestamp,
				COALESCE(previous_data::jsonb, '{}') AS previous_data,
				COALESCE(new_data::jsonb, '{}') AS new_data
			FROM public.user_credential_v2_log
		`)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"status": "Error", "message": err.Error()})
			return
		}
		defer rows.Close()

		var userLogs []struct {
			UserID          string          `json:"user_id"`
			ActionType      string          `json:"action_type"`
			ActionTimestamp string          `json:"action_timestamp"`
			PreviousData    json.RawMessage `json:"previous_data"`
			NewData         json.RawMessage `json:"new_data"`
		}

		for rows.Next() {
			var userLog struct {
				UserID          string          `json:"user_id"`
				ActionType      string          `json:"action_type"`
				ActionTimestamp string          `json:"action_timestamp"`
				PreviousData    json.RawMessage `json:"previous_data"`
				NewData         json.RawMessage `json:"new_data"`
			}

			err := rows.Scan(
				&userLog.UserID,
				&userLog.ActionType,
				&userLog.ActionTimestamp,
				&userLog.PreviousData,
				&userLog.NewData,
			)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"status": "Error", "message": err.Error()})
				return
			}

			userLogs = append(userLogs, userLog)
		}

		c.JSON(http.StatusOK, userLogs)
	})

	r.POST("/api/register", func(c *gin.Context) {
		if err := c.ShouldBindJSON(&user); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// emailDomainNotAllowed := map[string]bool{
		// 	"@gmail.com":   true,
		// 	"@yahoo.com":   true,
		// 	"@hotmail.com": true,
		// 	"@outlook.com": true,
		// }

		// emailParts := strings.Split(user.Username, "@")
		// if len(emailParts) == 2 && emailDomainNotAllowed["@"+emailParts[1]] {
		// 	c.JSON(http.StatusBadRequest, gin.H{"status": "Error", "message": "Only company email allowed"})
		// 	return
		// }

		// แฮชรหัสผ่านก่อนเก็บลงในฐานข้อมูล
		// hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost) <<<<<<<<<<< *********
		generatedPassword, err := generateRandomPassword(8)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"status": "Error", "message": err.Error()})
			return
		}
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(generatedPassword), bcrypt.DefaultCost)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"status": "Error", "message": err.Error()})
			return
		}
		hashedPasswordStr := string(hashedPassword)

		requires_action := "change_password"

		token, err := createTokenI(user.Username, requires_action)
		if err != nil {
			c.JSON(500, gin.H{"status": "Error", "message": "Failed to create token", "details": err.Error()})
			return
		}
		// emailErrChan := make(chan error, 1)
		// email := user.Username
		// go func() {
		// 	// ส่งอีเมลแจ้งผู้ใช้
		// 	to := user.Username
		// 	subject := "welcome! You have successfully registered."
		// 	body := "Please use the default password provided below to Login<br>"
		// 	body += "Email: " + email + "<br>"
		// 	body += "Password: " + generatedPassword + "<br>"
		// 	body += "<a href='http://localhost:3000/resetpassword/?token=" + token + "'>Confirm Link</a><br>"

		// 	// ส่งอีเมลและจับข้อผิดพลาด
		// 	if err := sendEmail(to, subject, body); err != nil {
		// 		log.Printf("เกิดข้อผิดพลาดในการส่งอีเมล: %s", err.Error())
		// 		emailErrChan <- err
		// 	} else {
		// 		emailErrChan <- nil
		// 	}
		// }()

		registrationComplete := make(chan bool)

		go func() {
			<-registrationComplete // รอการยืนยันว่าการลงทะเบียนเสร็จสมบูรณ์
			to := user.Username
			subject := "Welcome! You have successfully registered."
			body := "Please use the default password provided below to Login<br>" +
				"Email: " + user.Username + "<br>" +
				// "Password: " + generatedPassword + "<br>" +
				"<a href='https://partnerdemo.tracthai.com/resetpassword/?token=" + token + "'>Confirm Link</a><br>"
			if err := sendEmail(to, subject, body); err != nil {
				log.Printf("เกิดข้อผิดพลาดในการส่งอีเมล: %s", err.Error())
				c.JSON(http.StatusInternalServerError, gin.H{"status": "Error", "message": err.Error()})
			}
		}()
		var (
			cipherUsername, cipherUsername_token, cipherFirstname, cipherSurname, cipherFirstname_en, cipherSurname_en, cipherMobilePhone, cipherPersonalEmail, cipherCompanyName, cipherCompanyName_en, cipherCreditcard, cipherCreditcard_token string
			errChan                                                                                                                                                                                                                               = make(chan error, 12)
		)

		go func() {
			var err error
			cipherUsername, err = sendToFortanixSDKMSmaskingEmail(user.Username, keyUsername, keyPassword)
			errChan <- err
		}()

		go func() {
			var err error
			cipherUsername_token, err = sendToFortanixSDKMSMaskToken(user.Username, keyUsername, keyPassword)
			errChan <- err
		}()

		go func() {
			var err error
			cipherFirstname, err = sendToFortanixSDKMSTokenization(user.Firstname, keyUsername, keyPassword)
			errChan <- err
		}()

		go func() {
			var err error
			cipherSurname, err = sendToFortanixSDKMSTokenization(user.Surname, keyUsername, keyPassword)
			errChan <- err
		}()

		go func() {
			var err error
			cipherFirstname_en, err = sendToFortanixSDKMSTokenization(user.Firstname_en, keyUsername, keyPassword)
			errChan <- err
		}()

		go func() {
			var err error
			cipherSurname_en, err = sendToFortanixSDKMSTokenization(user.Surname_en, keyUsername, keyPassword)
			errChan <- err
		}()

		go func() {
			var err error
			cipherMobilePhone, err = sendToFortanixSDKMSmaskingMobilePhone(user.Mobile_phone, keyUsername, keyPassword)
			errChan <- err
		}()

		go func() {
			var err error
			cipherPersonalEmail, err = sendToFortanixSDKMSmaskingEmail(user.Personal_email, keyUsername, keyPassword)
			errChan <- err
		}()
		// user.Company_name = strings.Replace(user.Company_name, " ", "", -1)
		go func() {
			var err error
			cipherCompanyName, err = sendToFortanixSDKMSTokenization(user.Company_name, keyUsername, keyPassword)
			errChan <- err
		}()

		// user.Company_name_en = strings.Replace(user.Company_name_en, " ", "", -1)
		go func() {
			var err error
			cipherCompanyName_en, err = sendToFortanixSDKMSTokenization(user.Company_name_en, keyUsername, keyPassword)
			errChan <- err
		}()
		go func() {
			var err error
			cipherCreditcard, err = sendToFortanixSDKMSmaskingCreditcard(user.Credit_card, keyUsername, keyPassword)
			errChan <- err
		}()
		go func() {
			var err error
			cipherCreditcard_token, err = sendToFortanixSDKMSCreditCard(user.Credit_card, keyUsername, keyPassword)
			errChan <- err
		}()

		for i := 0; i < 12; i++ {
			if err := <-errChan; err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"status": "Error", "message": err.Error()})
				return
			}
		}

		// var checkUsernameExists struct {
		// 	UsernameToken string
		// }

		// err = db.QueryRow("SELECT username_token FROM user_credential_V2 WHERE username_token = $1", cipherUsername_token).Scan(&checkUsernameExists.UsernameToken)
		// if err == nil {
		// 	c.JSON(http.StatusConflict, gin.H{"status": "Error", "message": "Username already exists"})
		// 	return
		// } else if err != sql.ErrNoRows {
		// 	c.JSON(http.StatusInternalServerError, gin.H{"status": "Error", "message": err.Error()})
		// 	return
		// }

		var checkMobilePhoneExists struct {
			MobilePhone string
		}

		err = db.QueryRow("SELECT mobile_phone FROM user_credential_V2 WHERE mobile_phone = $1", cipherMobilePhone).Scan(&checkMobilePhoneExists.MobilePhone)
		if err == nil {
			c.JSON(http.StatusConflict, gin.H{"status": "Error", "message": "Mobile phone already exists"})
			return
		} else if err != sql.ErrNoRows {
			c.JSON(http.StatusInternalServerError, gin.H{"status": "Error", "message": err.Error()})
			return
		}

		emaildomain := user.Username
		splitEmail := strings.Split(emaildomain, "@")
		if len(splitEmail) != 2 {
			c.JSON(http.StatusBadRequest, gin.H{"status": "Error", "message": "Invalid email format"})
			return
		}
		domain := "@" + splitEmail[1]

		err = createUser(db, cipherUsername, cipherUsername_token, hashedPasswordStr, cipherFirstname, cipherSurname, cipherFirstname_en,
			cipherSurname_en, cipherMobilePhone, cipherPersonalEmail, cipherCompanyName, cipherCompanyName_en, user.Role, requires_action, cipherCreditcard, cipherCreditcard_token, domain, user.Country, user.Province, user.Amphoe, user.Tambon, user.Zipcode, user.Website, user.Address1, user.Address2, user.Title)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"statu": "Error", "message": err.Error()})
			return
		}
		registrationComplete <- true // แจ้ง goroutine ให้ดำเนินการส่งอีเมล
		c.JSON(http.StatusOK, gin.H{"status": "OK", "message": "User registered successfully"})
	})

	// r.PATCH("/api/change-password", AuthMiddleware(db), func(c *gin.Context) {
	r.PATCH("/api/change-password", func(c *gin.Context) {
		var updateRequest struct {
			Username        string `json:"username" binding:"required"`
			Oldpassword     string `json:"oldpassword"`
			Newpassword     string `json:"newpassword" binding:"required"`
			Requires_action string `json:"requires_action"`
		}
		if err := c.ShouldBindJSON(&updateRequest); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"status": "Error", "message": err.Error()})
			return
		}

		cipherUsername_update, err := sendToFortanixSDKMSMaskToken(updateRequest.Username, keyUsername, keyPassword)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"status": "Error", "message": err.Error()})
			return
		}

		// claims := c.MustGet("claims").(jwt.MapClaims)
		// email, ok := claims["username"].(string)
		// if !ok || email == "" {
		// 	c.JSON(401, gin.H{"status": "Error", "message": "Invalid token"})
		// 	return
		// }

		// Validate email
		// if email != updateRequest.Username || email == "" {
		// 	c.JSON(401, gin.H{"status": "Error", "message": "Invalid token or email"})
		// 	return
		// }

		oldpassword := updateRequest.Oldpassword
		newpassword := updateRequest.Newpassword
		requires_action := updateRequest.Requires_action
		// requires_action := updateRequest.Requires_action
		// Validate input
		if oldpassword == "" || newpassword == "" || len(oldpassword) < 8 || len(newpassword) < 8 {
			c.JSON(400, gin.H{"status": "Error", "message": "Invalid input"})
			return
		}
		// Verify the old password
		query := "SELECT password FROM user_credential_v2 WHERE username_token = $1"
		var hashedPassword string
		err = db.QueryRow(query, cipherUsername_update).Scan(&hashedPassword)
		if err != nil {
			if err == sql.ErrNoRows {
				c.JSON(401, gin.H{"status": "Error", "message": "User not found"})
				return
			}
			c.JSON(500, gin.H{"status": "Error", "message": "Database error", "details": err.Error()})
			return
		}

		err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(oldpassword))
		if err != nil {
			c.JSON(401, gin.H{"status": "Error", "message": "Incorrect Old Password"})
			return
		}

		// Update the password in the database with the new hashed password

		// err = updatePassword(db, cipherUsername_update, oldpassword, newpassword, requires_action)
		err = updatePassword(db, cipherUsername_update, oldpassword, newpassword, requires_action)
		if err != nil {
			c.JSON(500, gin.H{"status": "Error", "message": "Failed to update password", "details": err.Error()})
			return
		}
		// existingToken := c.GetHeader("Authorization")
		// existingToken = strings.TrimPrefix(existingToken, "Bearer ")
		// err = addToTokenBlacklist(db, existingToken, cipherUsername_update)
		// if err != nil {
		// 	c.JSON(500, gin.H{"status": "error", "message": "Failed to add blacklist token", "details": err.Error()})
		// }
		c.JSON(200, gin.H{"status": "OK", "message": "Password updated successfully"})
	})

	r.PATCH("/api/change-password-byconfirm-link", AuthMiddleware(db), func(c *gin.Context) {

		var updateRequest struct {
			Username        string `json:"username" binding:"required"`
			Newpassword     string `json:"newpassword" binding:"required"`
			Requires_action string `json:"requires_action"`
		}
		if err := c.ShouldBindJSON(&updateRequest); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"status": "Error", "message": err.Error()})
			return
		}

		cipherUsername_update, err := sendToFortanixSDKMSMaskToken(updateRequest.Username, keyUsername, keyPassword)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"status": "Error", "message": err.Error()})
			return
		}

		claims := c.MustGet("claims").(jwt.MapClaims)
		email, ok := claims["username"].(string)
		if !ok || email == "" {
			c.JSON(401, gin.H{"status": "Error", "message": "Invalid token"})
			return
		}

		// Validate email
		if email != updateRequest.Username || email == "" {
			c.JSON(401, gin.H{"status": "Error", "message": "Invalid token or email"})
			return
		}
		newpassword := updateRequest.Newpassword

		requires_action := updateRequest.Requires_action
		// Validate input
		if newpassword == "" || len(newpassword) < 8 {
			c.JSON(400, gin.H{"status": "Error", "message": "Invalid input"})
			return
		}

		// Update the password and requires_action in the database with the new hashed password
		err = updatePasswordI(db, newpassword, requires_action, cipherUsername_update)
		if err != nil {
			c.JSON(500, gin.H{"status": "Error", "message": "Failed to update password", "details": err.Error()})
			return
		}
		existingToken := c.GetHeader("Authorization")
		if existingToken == "" {
			// ไม่พบ token
			c.JSON(401, gin.H{"status": "Error", "message": "No token provided"})
			return
		}
		existingToken = strings.TrimPrefix(existingToken, "Bearer ")
		if existingToken == "" {
			// Token ไม่ถูกต้อง
			c.JSON(401, gin.H{"status": "Error", "message": "Invalid token format"})
			return
		}
		err = addToTokenBlacklist(db, existingToken, cipherUsername_update)
		if err != nil {
			c.JSON(500, gin.H{"status": "Error", "message": "Failed to add blacklist token", "details": err.Error()})
		}

		c.JSON(200, gin.H{"status": "OK", "message": "Password updated successfully"})
	})

	r.POST("/api/login", func(c *gin.Context) {
		var loginRequest struct {
			Username string `json:"username" binding:"required"`
			Password string `json:"password" binding:"required"`
		}

		if err := c.ShouldBindJSON(&loginRequest); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"status": "Error", "message": err.Error()})
			return
		}

		if !strings.Contains(loginRequest.Username, "@") || strings.HasSuffix(loginRequest.Username, "@") {
			c.JSON(http.StatusBadRequest, gin.H{"status": "Error", "message": "Username must be a valid email address"})
			return
		}

		cipherUsername, err := sendToFortanixSDKMSMaskToken(loginRequest.Username, keyUsername, keyPassword)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"status": "Error", "message": err.Error()})
			return
		}

		var StoredUser struct {
			ID                string
			Username          string
			UsernameOriginal  string
			UsernameToken     string
			PasswordHash      string
			FirstnameOriginal string
			SurnameOriginal   string
			FirstnameToken    string
			SurnameToken      string
			CompanyToken      string
			CompanyOriginal   string
			CreditCard        string
			CreditCardToken   string
			Requires_action   string
			// PersonalEmail    string
			Timestamp string
			Role      string
		}

		// err = db.QueryRow("SELECT id, username, username_token, password, personal_email, formatted_created_at, role FROM user_credential_V2 WHERE username = $1", cipherUsername).Scan(&StoredUser.ID, &StoredUser.Username, &StoredUser.UsernameToken, &StoredUser.Password, &StoredUser.PersonalEmail, &StoredUser.Timestamp, &StoredUser.Role)
		err = db.QueryRow("SELECT id, username,username_token, password, firstname_en, surname_en, formatted_created_at, company_name_en, credit_card, credit_card_token, requires_action, role FROM user_credential_v2 WHERE username_token = $1", cipherUsername).Scan(&StoredUser.ID, &StoredUser.Username, &StoredUser.UsernameToken, &StoredUser.PasswordHash, &StoredUser.FirstnameToken, &StoredUser.SurnameToken, &StoredUser.Timestamp, &StoredUser.CompanyToken, &StoredUser.CreditCard, &StoredUser.CreditCardToken, &StoredUser.Requires_action, &StoredUser.Role)
		if err == sql.ErrNoRows {
			c.JSON(http.StatusUnauthorized, gin.H{"status": "Error", "message": "User not found"})
			return
		} else if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"status": "Error", "message": err.Error()})
			return
		}

		// ทำการตรวจสอบรหัสผ่าน
		err = bcrypt.CompareHashAndPassword([]byte(StoredUser.PasswordHash), []byte(loginRequest.Password))
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"status": "Error", "message": "Invalid password"})
			return
		}

		// ดำเนินการ "detokenization" เพื่อหาค่า username ตั้งต้น
		// ในเส้น login api
		var (
			decodedUsername             []byte
			decodedCreditcard           []byte
			decodedCreditcardTokenBytes []byte
			// decodedUsernameToken        []byte
			decodedUsernameTokenBytes  []byte
			decodedFirstnameTokenBytes []byte
			// decodedSurnameToken        []byte
			decodedSurnameTokenBytes []byte
			// decodedCompanyToken      []byte
			decodedCompanyTokenBytes []byte
			errChan                  = make(chan error, 7)
		)

		go func() {
			var err error
			decodedUsername, err = base64.StdEncoding.DecodeString(StoredUser.Username)
			errChan <- err
		}()

		go func() {
			var err error
			decodedCreditcard, err = base64.StdEncoding.DecodeString(StoredUser.CreditCard)
			errChan <- err
		}()

		go func() {
			var err error
			decodedCreditcardMasked, err := detokenizationCreditCardMasked(StoredUser.CreditCardToken)
			if err != nil {
				errChan <- err
				return
			}
			decodedCreditcardTokenBytes, err = base64.StdEncoding.DecodeString(decodedCreditcardMasked)
			errChan <- err
		}()

		go func() {
			var err error
			decodedUsernameToken, err := detokenizeMaskToken(StoredUser.UsernameToken)
			if err != nil {
				errChan <- err
				return
			}
			decodedUsernameTokenBytes, err = base64.StdEncoding.DecodeString(string(decodedUsernameToken))
			errChan <- err
		}()

		go func() {
			var err error
			decodedFirstnameToken, err := detokenize(StoredUser.FirstnameToken)
			if err != nil {
				errChan <- err
				return
			}
			decodedFirstnameTokenBytes, err = base64.StdEncoding.DecodeString(string(decodedFirstnameToken))
			errChan <- err
		}()

		go func() {
			var err error
			decodedSurnameToken, err := detokenize(StoredUser.SurnameToken)
			if err != nil {
				errChan <- err
				return
			}
			decodedSurnameTokenBytes, err = base64.StdEncoding.DecodeString(string(decodedSurnameToken))
			errChan <- err
		}()

		go func() {
			var err error
			decodedCompanyToken, err := detokenize(StoredUser.CompanyToken)
			if err != nil {
				errChan <- err
				return
			}
			decodedCompanyTokenBytes, err = base64.StdEncoding.DecodeString(string(decodedCompanyToken))
			errChan <- err
		}()

		for i := 0; i < 7; i++ {
			if err := <-errChan; err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"status": "Error", "message": err.Error()})
				return
			}
		}
		expirationTime := time.Now().Add(24 * time.Hour)
		claims := CustomClaims{
			ID:               StoredUser.ID,
			Username:         string(decodedUsername),
			UsernameToken:    StoredUser.UsernameToken,
			UsernameOriginal: string(decodedUsernameTokenBytes),
			// PersonalEmail:    string(decodedPersonalEmail),
			PasswordHash:       StoredUser.PasswordHash,
			FirstnameOriginal:  string(decodedFirstnameTokenBytes),
			FirstnameToken:     StoredUser.FirstnameToken,
			SurnameOriginal:    string(decodedSurnameTokenBytes),
			SurnameToken:       StoredUser.SurnameToken,
			CompanyToken:       StoredUser.CompanyToken,
			CompanyOriginal:    string(decodedCompanyTokenBytes),
			CreditCardMasked:   string(decodedCreditcard),
			CreditCardOriginal: string(decodedCreditcardTokenBytes),
			Timestamp:          StoredUser.Timestamp,
			Requires_action:    StoredUser.Requires_action,
			Role:               StoredUser.Role,
			Exp:                expirationTime.Unix(),
		}

		tokenString, err := createJWT(claims)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"status": "Error", "message": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{"status": "OK", "message": "Successfully", "access_token": tokenString})
	})

	r.POST("/api/validate-domain", func(c *gin.Context) {
		var inputEmail struct {
			Username string `json:"username"`
		}

		if err := c.ShouldBindJSON(&inputEmail); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"status": "Error", "message": err.Error()})
			return
		}

		if !strings.Contains(inputEmail.Username, "@") || strings.HasSuffix(inputEmail.Username, "@") {
			c.JSON(http.StatusBadRequest, gin.H{"status": "Error", "message": "Username must be a valid email address"})
			return
		}

		var checkUsernameExists struct {
			UsernameToken string
		}

		cipherUsername_token, err := sendToFortanixSDKMSMaskToken(inputEmail.Username, keyUsername, keyPassword)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		err = db.QueryRow("SELECT username_token FROM user_credential_V2 WHERE username_token = $1", cipherUsername_token).Scan(&checkUsernameExists.UsernameToken)
		if err == nil {
			c.JSON(http.StatusConflict, gin.H{"status": "Error", "message": "Username already exists"})
			return
		} else if err != sql.ErrNoRows {
			c.JSON(http.StatusInternalServerError, gin.H{"status": "Error", "message": err.Error()})
			return
		}

		// if err := c.ShouldBindJSON(&inputEmail); err != nil {
		// 	c.JSON(http.StatusBadRequest, gin.H{"status": "Error", "message": err.Error()})
		// 	return
		// }

		emailDomainNotAllowed := map[string]bool{
			"@gmail.com":   true,
			"@yahoo.com":   true,
			"@hotmail.com": true,
			"@outlook.com": true,
		}

		emailParts := strings.Split(inputEmail.Username, "@")
		if len(emailParts) == 2 && emailDomainNotAllowed["@"+emailParts[1]] {
			c.JSON(http.StatusBadRequest, gin.H{"status": "Error", "message": "Only company email allowed"})
			return
		}

		email := inputEmail.Username

		// ใช้ strings.Split เพื่อแยกส่วนของอีเมล
		splitEmail := strings.Split(email, "@")

		// ตรวจสอบว่าได้สองส่วนหรือไม่
		if len(splitEmail) != 2 {
			// แจ้งข้อผิดพลาดหากอีเมลไม่ได้รูปแบบที่ถูกต้อง
			c.JSON(http.StatusBadRequest, gin.H{"status": "Error", "message": "Invalid email format"})
			return
		}

		// ใช้ส่วนที่สองของอีเมล (คือส่วนของโดเมน)
		emailDomain := "@" + splitEmail[1]

		var id, username, username_token, password, firstname, surname, firstname_en, surname_en, mobile_phone, personal_email, company_name, company_name_en, formatted_created_at, role, credit_card, credit_card_token, domain, country, province, amphoe, tambon, zipcode, website, address1, address2, title string
		err = db.QueryRow(`
    SELECT 
        id, 
        username, 
        username_token, 
        password, 
        firstname, 
        surname, 
        firstname_en, 
        surname_en, 
        mobile_phone, 
        personal_email, 
        company_name, 
        company_name_en, 
        formatted_created_at, 
        role, 
        credit_card, 
        credit_card_token, 
        domain,
		country,
		province,
		amphoe,
		tambon,
		zipcode,
		website,
		address1,
		address2,
		title
    FROM 
        user_credential_v2 
    WHERE 
        domain = $1
`, emailDomain).Scan(&id, &username, &username_token, &password, &firstname, &surname, &firstname_en, &surname_en, &mobile_phone, &personal_email, &company_name, &company_name_en, &formatted_created_at, &role, &credit_card, &credit_card_token, &domain, &country, &province, &amphoe, &tambon, &zipcode, &website, &address1, &address2, &title)

		if err != nil {
			if err == sql.ErrNoRows {
				c.JSON(http.StatusOK, gin.H{"match": false, "status": "Error", "message": "Domain does not match. To proceed, please check your email."})
			} else {
				log.Printf("Database query error: %v", err)

				c.JSON(http.StatusInternalServerError, gin.H{"status": "Error", "message": "Database query error"})
			}
			return
		}
		decodedCompanyToken, err := detokenize(company_name_en)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"status": "Error", "message": err.Error()})
			return
		}
		decodedCompanyTokenBytes, err := base64.StdEncoding.DecodeString(decodedCompanyToken)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"status": "Error", "message": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"status":  "OK",
			"match":   true,
			"message": "Domain matches",
			// "id":                       id,
			// "username":                 username,
			// "username_token":           username_token,
			// "password":                 password,
			// "firstname":                firstname,
			// "surname":                  surname,
			// "firstname_en":             firstname_en,
			// "surname_en":               surname_en,
			// "mobile_phone":             mobile_phone,
			// "personal_email":           personal_email,
			"company_name":         company_name,
			"company_name_en":      company_name_en,
			"formatted_created_at": formatted_created_at,
			"role":                 role,
			// "credit_card":              credit_card,
			// "credt_card_token":         credit_card_token,
			"domain":   domain,
			"country":  country,
			"province": province,
			"amphoe":   amphoe,
			"tambon":   tambon,
			"zipcode":  zipcode,
			"website":  website,
			"address1": address1,
			"address2": address2,
			// "title":                    title,
			"company_name_en_original": string(decodedCompanyTokenBytes),
		})
	})

	r.Run(":8011")
}

// func sendToFortanixSDKMSthai(data string, username, password string) (string, error) {
// 	// เปลี่ยน URL นี้เป็น URL ใหม่ที่คุณต้องการใช้
// 	fortanixAPIURL := "https://sdkms.fortanix.com/crypto/v1/keys/ca1bb6b4-7ee7-4a31-a033-7abef5452a79/encrypt"

// 	// แปลงข้อมูลเป็น Base64
// 	encodedData := base64.StdEncoding.EncodeToString([]byte(data))

// 	// ส่งข้อมูลไปยัง API พร้อมข้อมูลการรับรองความถูกต้อง (HTTP Basic Authentication)
// 	client := &http.Client{}
// 	reqBody := fmt.Sprintf(`{"alg": "AES", "mode": "FPE", "plain": "%s"}`, encodedData)
// 	req, err := http.NewRequest("POST", fortanixAPIURL, strings.NewReader(reqBody))
// 	if err != nil {
// 		return "", err
// 	}
// 	req.SetBasicAuth(username, password) // กำหนด username และ password ในการรับรองความถูกต้อง
// 	req.Header.Add("Content-Type", "application/json")
// 	resp, err := client.Do(req)
// 	if err != nil {
// 		return "", err
// 	}
// 	defer resp.Body.Close()

// 	// อ่านค่า "cipher" จากตอบรับ
// 	cipherData, err := io.ReadAll(resp.Body)
// 	if err != nil {
// 		return "", err
// 	}
// 	// fmt.Println("Response from Fortanix SDK MS:", string(cipherData)) // เพิ่มบรรทัดนี้

// 	// สร้าง JSON object จากค่า "cipher" เท่านั้น
// 	var result struct {
// 		Cipher string `json:"cipher"`
// 	}
// 	err = json.Unmarshal(cipherData, &result)
// 	if err != nil {
// 		return "", err
// 	}

//		return result.Cipher, nil
//	}
func sendToFortanixSDKMSTokenization(data string, username, password string) (string, error) {
	// เปลี่ยน URL นี้เป็น URL ใหม่ที่คุณต้องการใช้
	fortanixAPIURL := "https://sdkms.fortanix.com/crypto/v1/keys/2c197fdf-2db3-4021-8b7e-940630493f6a/encrypt"

	// แปลงข้อมูลเป็น Base64
	encodedData := base64.StdEncoding.EncodeToString([]byte(data))

	// ส่งข้อมูลไปยัง API พร้อมข้อมูลการรับรองความถูกต้อง (HTTP Basic Authentication)
	client := &http.Client{}
	reqBody := fmt.Sprintf(`{"alg": "AES", "mode": "FPE", "plain": "%s"}`, encodedData)
	req, err := http.NewRequest("POST", fortanixAPIURL, strings.NewReader(reqBody))
	if err != nil {
		return "", err
	}
	req.SetBasicAuth(username, password) // กำหนด username และ password ในการรับรองความถูกต้อง
	req.Header.Add("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	// อ่านค่า "cipher" จากตอบรับ
	cipherData, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	// fmt.Println("Response from Fortanix SDK MS:", string(cipherData)) // เพิ่มบรรทัดนี้

	// สร้าง JSON object จากค่า "cipher" เท่านั้น
	var result struct {
		Cipher string `json:"cipher"`
	}
	err = json.Unmarshal(cipherData, &result)
	if err != nil {
		return "", err
	}

	return result.Cipher, nil
}

func sendToFortanixSDKMSmaskingEmail(data string, username, password string) (string, error) {
	// fortanixAPIURL := "https://sdkms.fortanix.com/crypto/v1/keys/3c59e91b-8345-42f6-8386-f6a0365ca6ae/encrypt" // full masking
	fortanixAPIURL := "https://sdkms.fortanix.com/crypto/v1/keys/eaa7ec6a-b6ec-424c-b63a-fc3446c830b3/encrypt"

	// แปลงข้อมูลเป็น Base64
	encodedData := base64.StdEncoding.EncodeToString([]byte(data))

	// ส่งข้อมูลไปยัง API พร้อมข้อมูลการรับรองความถูกต้อง (HTTP Basic Authentication)
	client := &http.Client{}
	reqBody := fmt.Sprintf(`{"alg": "AES", "mode": "FPE", "plain": "%s"}`, encodedData)

	// เรียก API เส้นแรก เพื่อรับค่า "cipher"
	req1, err := http.NewRequest("POST", fortanixAPIURL, strings.NewReader(reqBody))
	if err != nil {
		return "", err
	}
	req1.SetBasicAuth(username, password)
	req1.Header.Add("Content-Type", "application/json")
	resp1, err := client.Do(req1)
	if err != nil {
		return "", err
	}
	defer resp1.Body.Close()

	// อ่านค่า "cipher" จากการเรียก API เส้นแรก
	cipherData, err := io.ReadAll(resp1.Body)
	if err != nil {
		return "", err
	}

	var cipherResult struct {
		Cipher string `json:"cipher"`
	}
	err = json.Unmarshal(cipherData, &cipherResult)
	if err != nil {
		return "", err
	}

	// เรียก API เส้นที่สอง เพื่อถอดรหัสค่า "cipher" เพื่อรับค่า "plain"
	// fortanixAPIURL2 := "https://sdkms.fortanix.com/crypto/v1/keys/3c59e91b-8345-42f6-8386-f6a0365ca6ae/decrypt"
	fortanixAPIURL2 := "https://sdkms.fortanix.com/crypto/v1/keys/eaa7ec6a-b6ec-424c-b63a-fc3446c830b3/decrypt"
	reqBody2 := fmt.Sprintf(`{"alg": "AES", "mode": "FPE", "cipher": "%s", "masked": true}`, cipherResult.Cipher)

	req2, err := http.NewRequest("POST", fortanixAPIURL2, strings.NewReader(reqBody2))
	if err != nil {
		return "", err
	}
	req2.SetBasicAuth(username, password)
	req2.Header.Add("Content-Type", "application/json")
	resp2, err := client.Do(req2)
	if err != nil {
		return "", err
	}
	defer resp2.Body.Close()

	// อ่านค่า "plain" จากการเรียก API เส้นที่สอง
	plainData, err := io.ReadAll(resp2.Body)
	if err != nil {
		return "", err
	}

	var plainResult struct {
		Plain string `json:"plain"`
	}
	err = json.Unmarshal(plainData, &plainResult)
	if err != nil {
		return "", err
	}

	return plainResult.Plain, nil
}

func sendToFortanixSDKMSMaskToken(data string, username, password string) (string, error) { /// token only
	// fortanixAPIURL := "https://sdkms.fortanix.com/crypto/v1/keys/3c59e91b-8345-42f6-8386-f6a0365ca6ae/encrypt"
	fortanixAPIURL := "https://sdkms.fortanix.com/crypto/v1/keys/eaa7ec6a-b6ec-424c-b63a-fc3446c830b3/encrypt"
	// แปลงข้อมูลเป็น Base64
	encodedData := base64.StdEncoding.EncodeToString([]byte(data))

	// ส่งข้อมูลไปยัง API พร้อมข้อมูลการรับรองความถูกต้อง (HTTP Basic Authentication)
	client := &http.Client{}
	reqBody := fmt.Sprintf(`{"alg": "AES", "mode": "FPE", "plain": "%s"}`, encodedData)
	req, err := http.NewRequest("POST", fortanixAPIURL, strings.NewReader(reqBody))
	if err != nil {
		return "", err
	}
	req.SetBasicAuth(username, password) // กำหนด username และ password ในการรับรองความถูกต้อง
	req.Header.Add("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	// อ่านค่า "cipher" จากตอบรับ
	cipherData, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	// สร้าง JSON object จากค่า "cipher" เท่านั้น
	var result struct {
		Cipher string `json:"cipher"`
	}
	err = json.Unmarshal(cipherData, &result)
	if err != nil {
		return "", err
	}

	return result.Cipher, nil
}

func detokenizeMaskToken(maskToken string) (string, error) {
	// fortanixAPIURL := "https://sdkms.fortanix.com/crypto/v1/keys/3c59e91b-8345-42f6-8386-f6a0365ca6ae/decrypt"
	fortanixAPIURL := "https://sdkms.fortanix.com/crypto/v1/keys/eaa7ec6a-b6ec-424c-b63a-fc3446c830b3/decrypt"

	// สร้าง JSON request โดยระบุ "cipher" ที่เป็นค่า "username_token"
	reqBody := fmt.Sprintf(`{"alg": "AES", "mode": "FPE", "cipher": "%s"}`, maskToken)

	client := &http.Client{}
	req, err := http.NewRequest("POST", fortanixAPIURL, strings.NewReader(reqBody))
	if err != nil {
		return "", err
	}

	// ตั้งค่าการรับรองความถูกต้อง (HTTP Basic Authentication)
	req.SetBasicAuth(keyUsername, keyPassword)
	req.Header.Add("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	// Log ตอบรับ
	responseBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	// log.Printf("Response from Fortanix API: %s", string(responseBytes))

	// อ่านค่า "plain" จากการเรียก API
	var result struct {
		Plain string `json:"plain"`
	}
	err = json.Unmarshal(responseBytes, &result)
	if err != nil {
		return "", err
	}

	return result.Plain, nil
}

// func sendToFortanixSDKMS(data string, username, password string) (string, error) { /// token only
// 	fortanixAPIURL := "https://sdkms.fortanix.com/crypto/v1/keys/6aff9f3f-afa3-40ee-9e38-355aba5c3cea/encrypt"

// 	// แปลงข้อมูลเป็น Base64
// 	encodedData := base64.StdEncoding.EncodeToString([]byte(data))

// 	// ส่งข้อมูลไปยัง API พร้อมข้อมูลการรับรองความถูกต้อง (HTTP Basic Authentication)
// 	client := &http.Client{}
// 	reqBody := fmt.Sprintf(`{"alg": "AES", "mode": "FPE", "plain": "%s"}`, encodedData)
// 	req, err := http.NewRequest("POST", fortanixAPIURL, strings.NewReader(reqBody))
// 	if err != nil {
// 		return "", err
// 	}
// 	req.SetBasicAuth(username, password) // กำหนด username และ password ในการรับรองความถูกต้อง
// 	req.Header.Add("Content-Type", "application/json")
// 	resp, err := client.Do(req)
// 	if err != nil {
// 		return "", err
// 	}
// 	defer resp.Body.Close()

// 	// อ่านค่า "cipher" จากตอบรับ
// 	cipherData, err := io.ReadAll(resp.Body)
// 	if err != nil {
// 		return "", err
// 	}

// 	// สร้าง JSON object จากค่า "cipher" เท่านั้น
// 	var result struct {
// 		Cipher string `json:"cipher"`
// 	}
// 	err = json.Unmarshal(cipherData, &result)
// 	if err != nil {
// 		return "", err
// 	}

// 	return result.Cipher, nil
// }

func sendToFortanixSDKMSmaskingMobilePhone(data string, username, password string) (string, error) {
	fortanixAPIURL := "https://sdkms.fortanix.com/crypto/v1/keys/b4270cbb-b82d-4b9c-8f7e-de677a6189ae/encrypt"

	// แปลงข้อมูลเป็น Base64
	encodedData := base64.StdEncoding.EncodeToString([]byte(data))

	// ส่งข้อมูลไปยัง API พร้อมข้อมูลการรับรองความถูกต้อง (HTTP Basic Authentication)
	client := &http.Client{}
	reqBody := fmt.Sprintf(`{"alg": "AES", "mode": "FPE", "plain": "%s"}`, encodedData)

	// เรียก API เส้นแรก เพื่อรับค่า "cipher"
	req1, err := http.NewRequest("POST", fortanixAPIURL, strings.NewReader(reqBody))
	if err != nil {
		return "", err
	}
	req1.SetBasicAuth(username, password)
	req1.Header.Add("Content-Type", "application/json")
	resp1, err := client.Do(req1)
	if err != nil {
		return "", err
	}
	defer resp1.Body.Close()

	// อ่านค่า "cipher" จากการเรียก API เส้นแรก
	cipherData, err := io.ReadAll(resp1.Body)
	if err != nil {
		return "", err
	}

	var cipherResult struct {
		Cipher string `json:"cipher"`
	}
	err = json.Unmarshal(cipherData, &cipherResult)
	if err != nil {
		return "", err
	}

	// เรียก API เส้นที่สอง เพื่อถอดรหัสค่า "cipher" เพื่อรับค่า "plain"
	fortanixAPIURL2 := "https://sdkms.fortanix.com/crypto/v1/keys/b4270cbb-b82d-4b9c-8f7e-de677a6189ae/decrypt"
	reqBody2 := fmt.Sprintf(`{"alg": "AES", "mode": "FPE", "cipher": "%s", "masked": true}`, cipherResult.Cipher)

	req2, err := http.NewRequest("POST", fortanixAPIURL2, strings.NewReader(reqBody2))
	if err != nil {
		return "", err
	}
	req2.SetBasicAuth(username, password)
	req2.Header.Add("Content-Type", "application/json")
	resp2, err := client.Do(req2)
	if err != nil {
		return "", err
	}
	defer resp2.Body.Close()

	// อ่านค่า "plain" จากการเรียก API เส้นที่สอง
	plainData, err := io.ReadAll(resp2.Body)
	if err != nil {
		return "", err
	}

	var plainResult struct {
		Plain string `json:"plain"`
	}
	err = json.Unmarshal(plainData, &plainResult)
	if err != nil {
		return "", err
	}

	return plainResult.Plain, nil
}

func sendToFortanixSDKMSCreditCard(data string, username, password string) (string, error) { /// token only
	fortanixAPIURL := "https://sdkms.fortanix.com/crypto/v1/keys/14d91b9f-c01c-4f9f-86b3-cc5473980aa5/encrypt"

	// แปลงข้อมูลเป็น Base64
	encodedData := base64.StdEncoding.EncodeToString([]byte(data))

	// ส่งข้อมูลไปยัง API พร้อมข้อมูลการรับรองความถูกต้อง (HTTP Basic Authentication)
	client := &http.Client{}
	reqBody := fmt.Sprintf(`{"alg": "AES", "mode": "FPE", "plain": "%s"}`, encodedData)
	req, err := http.NewRequest("POST", fortanixAPIURL, strings.NewReader(reqBody))
	if err != nil {
		return "", err
	}
	req.SetBasicAuth(username, password) // กำหนด username และ password ในการรับรองความถูกต้อง
	req.Header.Add("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	// อ่านค่า "cipher" จากตอบรับ
	cipherData, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	// สร้าง JSON object จากค่า "cipher" เท่านั้น
	var result struct {
		Cipher string `json:"cipher"`
	}
	err = json.Unmarshal(cipherData, &result)
	if err != nil {
		return "", err
	}

	return result.Cipher, nil
}

func sendToFortanixSDKMSmaskingCreditcard(data string, username, password string) (string, error) {
	fortanixAPIURL := "https://sdkms.fortanix.com/crypto/v1/keys/14d91b9f-c01c-4f9f-86b3-cc5473980aa5/encrypt"

	// แปลงข้อมูลเป็น Base64
	encodedData := base64.StdEncoding.EncodeToString([]byte(data))

	// ส่งข้อมูลไปยัง API พร้อมข้อมูลการรับรองความถูกต้อง (HTTP Basic Authentication)
	client := &http.Client{}
	reqBody := fmt.Sprintf(`{"alg": "AES", "mode": "FPE", "plain": "%s"}`, encodedData)

	// เรียก API เส้นแรก เพื่อรับค่า "cipher"
	req1, err := http.NewRequest("POST", fortanixAPIURL, strings.NewReader(reqBody))
	if err != nil {
		return "", err
	}
	req1.SetBasicAuth(username, password)
	req1.Header.Add("Content-Type", "application/json")
	resp1, err := client.Do(req1)
	if err != nil {
		return "", err
	}
	defer resp1.Body.Close()

	// อ่านค่า "cipher" จากการเรียก API เส้นแรก
	cipherData, err := io.ReadAll(resp1.Body)
	if err != nil {
		return "", err
	}

	var cipherResult struct {
		Cipher string `json:"cipher"`
	}
	err = json.Unmarshal(cipherData, &cipherResult)
	if err != nil {
		return "", err
	}

	// เรียก API เส้นที่สอง เพื่อถอดรหัสค่า "cipher" เพื่อรับค่า "plain"
	fortanixAPIURL2 := "https://sdkms.fortanix.com/crypto/v1/keys/14d91b9f-c01c-4f9f-86b3-cc5473980aa5/decrypt"
	reqBody2 := fmt.Sprintf(`{"alg": "AES", "mode": "FPE", "cipher": "%s", "masked": true}`, cipherResult.Cipher)

	req2, err := http.NewRequest("POST", fortanixAPIURL2, strings.NewReader(reqBody2))
	if err != nil {
		return "", err
	}
	req2.SetBasicAuth(username, password)
	req2.Header.Add("Content-Type", "application/json")
	resp2, err := client.Do(req2)
	if err != nil {
		return "", err
	}
	defer resp2.Body.Close()

	// อ่านค่า "plain" จากการเรียก API เส้นที่สอง
	plainData, err := io.ReadAll(resp2.Body)
	if err != nil {
		return "", err
	}

	var plainResult struct {
		Plain string `json:"plain"`
	}
	err = json.Unmarshal(plainData, &plainResult)
	if err != nil {
		return "", err
	}

	return plainResult.Plain, nil
}

func createUser(db *sql.DB, cipherUsername, usernameToken, hashedPassword, cipherFirstname, cipherSurname, cipherFirstname_en, cipherSurname_en, cipherMobilePhone, cipherPersonalEmail, cipherCompanyName, cipherCompanyName_en, Role, requires_action, cipherCreditcard, cipherCreditcard_token, domain, Country, Province, Amphoe, Tambon, Zipcode, Website, Address1, Address2, Title string) error {
	query := `
        INSERT INTO user_credential_V2 (username, username_token, password, firstname, surname, firstname_en, surname_en, mobile_phone,
            personal_email, company_name, company_name_en, role, created_at, formatted_created_at, requires_action, credit_card, credit_card_token, domain, country, province, amphoe, tambon, zipcode, website, address1, address2, title)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, NOW(), EXTRACT(epoch FROM NOW()), $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25)`
	// _, err := db.Exec(query, cipherUsername, usernameToken, hashedPassword, cipherFirstname, cipherSurname, cipherFirstname_en, cipherSurname_en, cipherMobilePhone, cipherPersonalEmail, cipherCompanyName, cipherCompanyName_en, Role, requires_action, cipherCreditcard, cipherCreditcard_token, domain, Country, Province, Amphoe, Tambon, Zipcode, Website, Address1, Address2, user.Title)
	_, err := db.Exec(query, cipherUsername, usernameToken, hashedPassword, cipherFirstname, cipherSurname, cipherFirstname_en, cipherSurname_en, cipherMobilePhone, cipherPersonalEmail, cipherCompanyName, cipherCompanyName_en, Role, requires_action, cipherCreditcard, cipherCreditcard_token, domain, Country, Province, Amphoe, Tambon, Zipcode, Website, Address1, Address2, Title)
	if err != nil {
		return err
	}

	return nil
}

// func detokenizeUsernameToken(usernameToken string) (string, error) {
// 	fortanixAPIURL := "https://sdkms.fortanix.com/crypto/v1/keys/6aff9f3f-afa3-40ee-9e38-355aba5c3cea/decrypt"

// 	// สร้าง JSON request โดยระบุ "cipher" ที่เป็นค่า "username_token"
// 	reqBody := fmt.Sprintf(`{"alg": "AES", "mode": "FPE", "cipher": "%s"}`, usernameToken)

// 	client := &http.Client{}
// 	req, err := http.NewRequest("POST", fortanixAPIURL, strings.NewReader(reqBody))
// 	if err != nil {
// 		return "", err
// 	}

// 	// ตั้งค่าการรับรองความถูกต้อง (HTTP Basic Authentication)
// 	req.SetBasicAuth(keyUsername, keyPassword)
// 	req.Header.Add("Content-Type", "application/json")
// 	resp, err := client.Do(req)
// 	if err != nil {
// 		return "", err
// 	}
// 	defer resp.Body.Close()

// 	// Log ตอบรับ
// 	responseBytes, err := io.ReadAll(resp.Body)
// 	if err != nil {
// 		return "", err
// 	}
// 	// log.Printf("Response from Fortanix API: %s", string(responseBytes))

// 	// อ่านค่า "plain" จากการเรียก API
// 	var result struct {
// 		Plain string `json:"plain"`
// 	}
// 	err = json.Unmarshal(responseBytes, &result)
// 	if err != nil {
// 		return "", err
// 	}

// 	return result.Plain, nil
// }

func detokenize(usernameToken string) (string, error) {
	fortanixAPIURL := "https://sdkms.fortanix.com/crypto/v1/keys/2c197fdf-2db3-4021-8b7e-940630493f6a/decrypt"

	// สร้าง JSON request โดยระบุ "cipher" ที่เป็นค่า "username_token"
	reqBody := fmt.Sprintf(`{"alg": "AES", "mode": "FPE", "cipher": "%s"}`, usernameToken)

	client := &http.Client{}
	req, err := http.NewRequest("POST", fortanixAPIURL, strings.NewReader(reqBody))
	if err != nil {
		return "", err
	}

	// ตั้งค่าการรับรองความถูกต้อง (HTTP Basic Authentication)
	req.SetBasicAuth(keyUsername, keyPassword)
	req.Header.Add("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	// Log ตอบรับ
	responseBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	// log.Printf("Response from Fortanix API: %s", string(responseBytes))

	// อ่านค่า "plain" จากการเรียก API
	var result struct {
		Plain string `json:"plain"`
	}
	err = json.Unmarshal(responseBytes, &result)
	if err != nil {
		return "", err
	}

	return result.Plain, nil
}

func detokenizationCreditCardMasked(creditcard string) (string, error) {
	fortanixAPIURL := "https://sdkms.fortanix.com/crypto/v1/keys/14d91b9f-c01c-4f9f-86b3-cc5473980aa5/decrypt"

	// สร้าง JSON request โดยระบุ "cipher" ที่เป็นค่า "username_token"
	reqBody := fmt.Sprintf(`{"alg": "AES", "mode": "FPE", "cipher": "%s"}`, creditcard)

	client := &http.Client{}
	req, err := http.NewRequest("POST", fortanixAPIURL, strings.NewReader(reqBody))
	if err != nil {
		return "", err
	}

	// ตั้งค่าการรับรองความถูกต้อง (HTTP Basic Authentication)
	req.SetBasicAuth(keyUsername, keyPassword)
	req.Header.Add("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	// Log ตอบรับ
	responseBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	// log.Printf("Response from Fortanix API: %s", string(responseBytes))

	// อ่านค่า "plain" จากการเรียก API
	var result struct {
		Plain string `json:"plain"`
	}
	err = json.Unmarshal(responseBytes, &result)
	if err != nil {
		return "", err
	}

	return result.Plain, nil
}

func createJWT(claims CustomClaims) (string, error) {
	// สร้าง Token ด้วย claims และกุญแจลับ
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// ลาก Token ไปเป็น string
	tokenString, err := token.SignedString([]byte("thenilalive"))

	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func (c CustomClaims) Valid() error {
	if time.Unix(c.Exp, 0).Before(time.Now()) {
		return errors.New("token has expired")
	}
	return nil
}

func AdminOnly() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := c.GetHeader("Authorization")
		if tokenString == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"status": "Error", "message": "Authorization header missing"})
			c.Abort()
			return
		}

		tokenString = strings.TrimPrefix(tokenString, "Bearer ")
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			// ในกรณีนี้ให้ใช้ secret key ของคุณเพื่อตรวจสอบลายเซน JWT
			return []byte("thenilalive"), nil
		})

		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"status": "Error", "message": "Invalid or expired token"})
			c.Abort()
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"status": "Error", "message": "Invalid token claims"})
			c.Abort()
			return
		}

		role, ok := claims["role"].(string)
		if !ok || role != "admin" {
			c.JSON(http.StatusForbidden, gin.H{"status": "Error", "message": "permission denied : Admin only"})
			c.Abort()
			return
		}

		c.Next()
	}
}
func Decryptthai(encryptedData string) (string, error) {
	fortanixAPIURL := "https://sdkms.fortanix.com/crypto/v1/keys/ca1bb6b4-7ee7-4a31-a033-7abef5452a79/decrypt"
	reqBody := fmt.Sprintf(`{"alg": "AES", "mode": "FPE", "cipher": "%s"}`, encryptedData)

	client := &http.Client{}
	req, err := http.NewRequest("POST", fortanixAPIURL, strings.NewReader(reqBody))
	if err != nil {
		return "", err
	}

	// ตั้งค่าการรับรองความถูกต้อง (HTTP Basic Authentication)
	req.SetBasicAuth(keyUsername, keyPassword)
	req.Header.Add("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	// Log ตอบรับ
	responseBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	// log.Printf("Response from Fortanix API: %s", string(responseBytes))

	// อ่านค่า "plain" จากการเรียก API
	var result struct {
		Plain string `json:"plain"`
	}
	err = json.Unmarshal(responseBytes, &result)
	if err != nil {
		return "", err
	}

	return result.Plain, nil
}

func sendEmail(to, subject, body string) error {
	// กำหนดข้อมูลสำหรับเข้าระบบ SMTP
	smtpServer := "smtp.gmail.com"
	smtpPort := 587
	senderEmail := "report.trac@gmail.com"
	senderPassword := "mcoqvwpabjtdoxvw"

	// กำหนดข้อมูลอีเมล
	from := senderEmail
	recipients := []string{to}

	// Create the email content in HTML format
	msg := []byte("To: " + to + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"MIME-Version: 1.0;\r\n" +
		"Content-Type: text/html; charset=\"UTF-8\";\r\n" +
		"\r\n" +
		body)

	// ติดต่อ SMTP เซิร์ฟเวอร์และส่งอีเมล
	auth := smtp.PlainAuth("", senderEmail, senderPassword, smtpServer)
	err := smtp.SendMail(fmt.Sprintf("%s:%d", smtpServer, smtpPort), auth, from, recipients, msg)
	return err
}

func generateRandomPassword(length int) (string, error) {
	// สร้างตัวชี้เพื่อใช้ในการสร้างรหัสผ่านแบบสุ่ม
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	seededRand := rand.New(rand.NewSource(time.Now().UnixNano()))

	// สร้างรหัสผ่านแบบสุ่มด้วยความยาวที่กำหนด
	password := make([]byte, length)
	for i := range password {
		password[i] = charset[seededRand.Intn(len(charset))]
	}
	return string(password), nil
}

var jwtSecret = []byte("not-key") // Replace "your-secret-key" with your actual secret key

func createTokenI(email string, requires_action string) (string, error) {
	// Set expiration time based on the remember parameter
	expirationTime := time.Now().Add(24 * time.Hour)

	// Creating the token
	token := jwt.New(jwt.GetSigningMethod("HS256"))
	claims := token.Claims.(jwt.MapClaims)
	claims["username"] = email
	claims["requires_action"] = requires_action // fixed the typo and added this field to the token
	claims["exp"] = expirationTime.Unix()       // Token expiration time

	// Signing the token with a secret
	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

// func updatePassword(db *sql.DB, cipherUsername_update, oldpassword, newpassword, requires_action string) error {
func updatePassword(db *sql.DB, cipherUsername_update, oldpassword, newpassword, requires_action string) error {
	// Hash the old password
	var hashedOldPassword string
	query := "SELECT password FROM user_credential_v2 WHERE username_token = $1"
	err := db.QueryRow(query, cipherUsername_update).Scan(&hashedOldPassword)
	if err != nil {
		if err == sql.ErrNoRows {
			return errors.New("user not found")
		}
		return err
	}

	// Check the old password
	err = bcrypt.CompareHashAndPassword([]byte(hashedOldPassword), []byte(oldpassword))
	if err != nil {
		return errors.New("incorrect old password")
	}

	// Hash the new password
	hashedNewPassword, err := bcrypt.GenerateFromPassword([]byte(newpassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	// Update password and requires_action in the database
	query = "UPDATE user_credential_v2 SET password = $1, requires_action = $2  WHERE username_token = $3"
	_, err = db.Exec(query, string(hashedNewPassword), requires_action, cipherUsername_update)

	return err
}

func AuthMiddleware(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		providedToken := c.Request.Header.Get("Authorization")

		if providedToken == "" {
			c.JSON(401, gin.H{"status": "Error", "message": "Missing token"})
			c.Abort()
			return
		}

		// Extract the token from the "Bearer <token>" format
		providedToken = strings.TrimPrefix(providedToken, "Bearer ")

		if isTokenBlacklisted(db, providedToken) {
			c.JSON(http.StatusUnauthorized, gin.H{"status": "Error", "message": "THE TOKEN ALREADY USED : ONE TIME TOKEN"})
			c.Abort()
			return
		}

		// Verify the token
		token, err := jwt.Parse(providedToken, func(token *jwt.Token) (interface{}, error) {
			return jwtSecret, nil
		})

		if err != nil || !token.Valid {
			c.JSON(401, gin.H{"status": "Error", "message": "Invalid Token"})
			c.Abort()
			return
		}

		// Set the claims in the context
		c.Set("claims", token.Claims)

		c.Next()
	}
}

func addToTokenBlacklist(db *sql.DB, token string, cipherUsername_update string) error {
	// สมมติว่าคุณต้องการอัปเดตคอลัมน์ blacklist_token ในตาราง personaldetails
	// โดยต้องระบุ email ของผู้ใช้ที่เกี่ยวข้อง
	query := "UPDATE user_credential_v2 SET blacklist_token = $1 WHERE username_token = $2"

	_, err := db.Exec(query, token, cipherUsername_update)
	if err != nil {
		return err
	}
	return nil
}

func updatePasswordI(db *sql.DB, newpassword, requires_action, cipherUsername_update string) error {
	// Hash the new password
	hashedNewPassword, err := bcrypt.GenerateFromPassword([]byte(newpassword), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("Error hashing password: %v", err)
		return err
	}

	// Update password and requires_action in the databasine
	query := "UPDATE user_credential_v2 SET password = $1, requires_action = $2 WHERE username_token = $3"
	_, err = db.Exec(query, string(hashedNewPassword), requires_action, cipherUsername_update)
	log.Printf("Error updating password in database: %v", err)
	return err
}

func isTokenBlacklisted(db *sql.DB, token string) bool {
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM user_credential_v2 WHERE blacklist_token = $1", token).Scan(&count)
	if err != nil {
		// จัดการข้อผิดพลาด
		return false
	}
	return count > 0
}
