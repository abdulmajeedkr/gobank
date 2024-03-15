package main

import (
	"math/rand"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type LoginResponse struct {
	Number int64  `json:"number"`
	Token  string `json:"token"`
}

type LoginRequest struct {
	Number   int64  `json:"number"`
	Password string `json:"password"`
}

type TransferRequest struct {
	ToAccount int `json:"toAccount"`
	Ammount   int `json:"ammount"`
}

type CreateAccountRequest struct {
	FirstName string `json:"firstname"`
	LastName  string `json:"lastname"`
	Password  string `json:"password"`
}

type Account struct {
	ID                int       `json:"id"`
	FirstName         string    `json:"firstname"`
	LastName          string    `json:"lastname"`
	Number            int64     `json:"number"`
	EncryptedPassword string    `json:"-"`
	Balance           int64     `json:"balance"`
	CreatedAt         time.Time `json:"createdAt"`
}

func (a *Account) ValidatePassword(pw string) bool {
	return (bcrypt.CompareHashAndPassword([]byte(a.EncryptedPassword), []byte(pw)) == nil)
}

func NewAccount(firstname, lastname, password string) (*Account, error) {
	encpw, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	return &Account{
		ID:                0,
		FirstName:         firstname,
		LastName:          lastname,
		Number:            int64(rand.Intn(10000)),
		EncryptedPassword: string(encpw),
		Balance:           0,
		CreatedAt:         time.Now().UTC(),
	}, nil
}