package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/alexedwards/scs/v2"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/time/rate"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// --- Models ---

type User struct {
	ID           uint      `gorm:"primaryKey" json:"id"`
	Username     string    `gorm:"unique;not null" json:"username"`
	PasswordHash string    `gorm:"not null" json:"-"`
	SaldoPluse   float64   `gorm:"type:decimal(12,2);default:0.00" json:"saldo_pluse"`
	PublicHash   string    `gorm:"unique" json:"public_hash"`
	CreatedAt    time.Time `json:"created_at"`
}

type Transaction struct {
	ID            uint      `gorm:"primaryKey" json:"id"`
	UserID        uint      `json:"user_id"`
	ToUserID      *uint     `json:"to_user_id"`
	Tipo          string    `json:"tipo"` // entrada, saida, transferencia_enviada, transferencia_recebida, pagamento_api
	ValorBRL      float64   `gorm:"type:decimal(12,2)" json:"valor_brl"`
	ValorETH      float64   `gorm:"type:decimal(18,8)" json:"valor_eth"`
	TxHash        string    `gorm:"unique" json:"tx_hash"`
	BlockHash     string    `json:"block_hash"`
	Status        string    `gorm:"default:'pendente'" json:"status"`
	DataPagamento time.Time `gorm:"default:CURRENT_TIMESTAMP" json:"data_pagamento"`
}

type APIKey struct {
	ID         uint      `gorm:"primaryKey" json:"id"`
	UserID     uint      `json:"user_id"`
	Key        string    `gorm:"unique;column:api_key" json:"api_key"`
	SiteName   string    `gorm:"not null" json:"site_name"`
	SiteURL    string    `json:"site_url"`
	LogoURL    string    `json:"logo_url"`
	WebhookURL string    `json:"webhook_url"`
	Ativo      bool      `gorm:"default:true" json:"ativo"`
	CreatedAt  time.Time `json:"created_at"`
}

type PaymentLink struct {
	ID        uint       `gorm:"primaryKey" json:"id"`
	APIKeyID  uint       `json:"api_key_id"`
	Token     string     `gorm:"unique;column:link_token" json:"link_token"`
	ValorBRL  float64    `gorm:"type:decimal(12,2)" json:"valor_brl"`
	Descricao string     `json:"descricao"`
	ClienteID string     `json:"cliente_id"`
	Status    string     `gorm:"default:'pendente'" json:"status"`
	TxHash    string     `json:"tx_hash"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt time.Time  `json:"expires_at"`
	PaidAt    *time.Time `json:"paid_at"`
}

// --- Globals ---

var (
	db             *gorm.DB
	sessionManager *scs.SessionManager
	limiter        = rate.NewLimiter(1, 5) // 1 req/sec, burst of 5
)

// --- Security Helpers ---

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	return string(bytes), err
}

func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func generatePublicHash(uid uint) string {
	data := fmt.Sprintf("payplus_user_%d_salt_k9x", uid)
	hash := sha256.Sum256([]byte(data))
	return "0x" + hex.EncodeToString(hash[:])[:40]
}

func generateBlockHash(uid uint, ts int64) string {
	data := fmt.Sprintf("block_%d_%d_payplus", uid, ts)
	hash := sha256.Sum256([]byte(data))
	return "0x" + hex.EncodeToString(hash[:])
}

// FIX: Validação de URL rigorosa
func isValidURL(str string) bool {
	if str == "" {
		return true
	}
	u, err := url.ParseRequestURI(str)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return false
	}
	return true
}

// FIX: HMAC correto para webhooks (usando uma chave secreta dedicada)
func computeHmac(message, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(message))
	return hex.EncodeToString(h.Sum(nil))
}

// --- Middlewares ---

func rateLimitMiddleware(c *gin.Context) {
	if !limiter.Allow() {
		c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": "Muitas requisições. Tente novamente em instantes."})
		return
	}
	c.Next()
}

func authRequired(c *gin.Context) {
	userID := sessionManager.GetInt(c.Request.Context(), "user_id")
	if userID == 0 {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Não autenticado"})
		c.Abort()
		return
	}
	c.Set("user_id", uint(userID))
	c.Next()
}

// --- Handlers ---

func verifyTurnstile(token string) bool {
	// FIX: Puxar do .env explicitamente para evitar colisão
	secret := os.Getenv("CF_SECRET_KEY")
	if secret == "" {
		log.Println("CRÍTICO: CF_SECRET_KEY não configurada no ambiente.")
		return false
	}

	if token == "" {
		return false
	}

	client := &http.Client{Timeout: 5 * time.Second}
	data := url.Values{
		"secret":   {secret},
		"response": {token},
	}

	resp, err := client.PostForm("https://challenges.cloudflare.com/turnstile/v0/siteverify", data)
	if err != nil {
		log.Printf("Erro ao verificar Turnstile: %v", err)
		return false
	}
	defer resp.Body.Close()

	var result struct {
		Success bool `json:"success"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false
	}

	return result.Success
}

func handleRegister(c *gin.Context) {
	var req struct {
		Username string `form:"username" binding:"required,min=3"`
		Password string `form:"password" binding:"required,min=6"`
		Token    string `form:"cf-turnstile-response"`
	}

	if err := c.ShouldBind(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Dados inválidos"})
		return
	}

	// Verificação anti-bot obrigatória
	if !verifyTurnstile(req.Token) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Falha na verificação anti-bot"})
		return
	}

	hashedPassword, _ := hashPassword(req.Password)
	user := User{
		Username:     req.Username,
		PasswordHash: hashedPassword,
	}

	if err := db.Create(&user).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Usuário já existe"})
		return
	}

	user.PublicHash = generatePublicHash(user.ID)
	db.Save(&user)

	c.JSON(http.StatusCreated, gin.H{"message": "Conta criada com sucesso"})
}

func handleLogin(c *gin.Context) {
	username := c.PostForm("username")
	password := c.PostForm("password")

	var user User
	if err := db.Where("username = ?", username).First(&user).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Credenciais inválidas"})
		return
	}

	if !checkPasswordHash(password, user.PasswordHash) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Credenciais inválidas"})
		return
	}

	// FIX: Session Fixation - Regenerate session after login
	if err := sessionManager.RenewToken(c.Request.Context()); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Erro interno de sessão"})
		return
	}

	sessionManager.Put(c.Request.Context(), "user_id", int(user.ID))
	sessionManager.Put(c.Request.Context(), "username", user.Username)

	c.JSON(http.StatusOK, gin.H{"message": "Login realizado"})
}

func handleExplorer(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))

	if limit > 100 {
		limit = 100
	}

	var txs []Transaction
	db.Order("data_pagamento desc").Limit(limit).Offset(offset).Find(&txs)

	c.JSON(http.StatusOK, gin.H{"txs": txs})
}

func main() {
	// FIX: Puxar do .env explicitamente e configurar SSL
	dbURL := os.Getenv("DATABASE_URL")
	appSecret := os.Getenv("SECRET_KEY") 

	if dbURL == "" || appSecret == "" {
		log.Fatal("Variáveis de ambiente DATABASE_URL e SECRET_KEY são obrigatórias.")
	}

	// Configuração de SSL para o PostgreSQL se as variáveis de certificado estiverem presentes
	sslMode := os.Getenv("PG_SSL_MODE")
	caCert := os.Getenv("PG_CA_CERT")
	clientCert := os.Getenv("PG_CLIENT_CERT")
	clientKey := os.Getenv("PG_CLIENT_KEY")

	if sslMode != "" {
		dbURL = fmt.Sprintf("%s?sslmode=%s&sslrootcert=%s&sslcert=%s&sslkey=%s", 
			dbURL, sslMode, caCert, clientCert, clientKey)
	}

	var err error
	db, err = gorm.Open(postgres.Open(dbURL), &gorm.Config{})
	if err != nil {
		log.Fatal("Erro ao conectar ao banco:", err)
	}

	db.AutoMigrate(&User{}, &Transaction{}, &APIKey{}, &PaymentLink{})

	// Configuração de Sessão Segura
	sessionManager = scs.New()
	sessionManager.Lifetime = 24 * time.Hour
	sessionManager.Cookie.HttpOnly = true
	sessionManager.Cookie.SameSite = http.SameSiteStrictMode
	sessionManager.Cookie.Secure = os.Getenv("ENV") == "production"

	r := gin.Default()

	r.POST("/register", handleRegister)
	r.POST("/login", handleLogin)
	r.GET("/api/explorer", handleExplorer)

	api := r.Group("/api")
	api.Use(rateLimitMiddleware)
	api.Use(authRequired)
	{
		api.POST("/check-payment", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"status": "ok"})
		})
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	r.Run(":" + port)
}

