package gotrs

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/gabriel-vasile/mimetype"
)

var (
	config = &OTRSConfig{
		BaseURL: "otrs/nph-genericinterface.pl/Webservice/",
		Connector: TicketConnector{
			Name: "GenericTicketConnectorREST",
			API: map[string]*APIMethod{
				"SessionCreate": &APIMethod{
					ReqMethod: "POST",
					Route:     "/Session",
					Result:    "SessionID",
				},
				"TicketSearch": &APIMethod{
					ReqMethod: "GET",
					Route:     "/Ticket",
					Result:    "TicketID",
				},
				"TicketGet": &APIMethod{
					ReqMethod: "GET",
					Route:     "/Ticket/:TicketID",
					Result:    "TicketID",
				},
				"TicketCreate": &APIMethod{
					ReqMethod: "POST",
					Route:     "/Ticket",
					Result:    "TicketID",
				},
				"TicketUpdate": &APIMethod{
					ReqMethod: "PATCH",
					Route:     "/Ticket/:TicketID",
					Result:    "TicketID",
				},
			},
		},
	}
)

// APIMethod - объект запроса на API OTRS
type APIMethod struct {
	ReqMethod string `yaml:"req_method"`
	Route     string `yaml:"route"`
	Result    string `yaml:"result"`
	Login     bool   `yaml:"login"`
}

// OTRSErrorResponse - ответ OTRS на запрос с ошибкой
type OTRSErrorResponse struct {
	Error struct {
		ErrorMessage string `json:"ErrorMessage"`
		ErrorCode    string `json:"ErrorCode"`
	} `json:"Error"`
}

// TicketConnector - набор методов API OTRS
type TicketConnector struct {
	Name string
	API  map[string]*APIMethod
}

// OTRSConfig - базовый конфиг настройки запросов в OTRS
type OTRSConfig struct {
	BaseAddress string
	BaseURL     string
	Connector   TicketConnector
}

// OTRSClient - клиент для работы с API сервиса OTRS
type OTRSClient struct {
	Login     string `json:"UserLogin"`
	Password  string `json:"Password"`
	SessionID string `json:"SessionID,omitempty"`
}

// Article - объект статьи в тикете
type Article struct {
	Body     string `json:"Body"`
	Charset  string `json:"Charset"`
	Subject  string `json:"Subject"`
	TimeUnit int    `json:"TimeUnit"`
	MimeType string `json:"MimeType"`
}

// DynField - объект динамического поля в тикете
type DynField struct {
	Name        string `json:"-"`
	Value       string `json:"-"`
	SearchValue string `json:"-"`
}

// Attachment - объект прикрепляемого файла - вложения
type Attachment struct {
	Content     string `json:"Content"`
	ContentType string `json:"ContentType"`
	Filename    string `json:"Filename"`
}

// TicketTime - кастомный формат времени для тикета
type TicketTime time.Time

// Ticket - основной объект тикета
type Ticket struct {
	TicketID     int        `json:"TicketID"`
	TicketNumber string     `json:"TicketNumber,omitempty"`
	Title        string     `json:"Title,omitempty"`
	QueueID      int        `json:"QueueID,omitempty"`
	Queue        string     `json:"Queue,omitempty"`
	TypeID       int        `json:"TypeID,omitempty"`
	Type         string     `json:"Type,omitempty"`
	StateID      int        `json:"StateID,omitempty"`
	State        string     `json:"State,omitempty"`
	PriorityID   int        `json:"PriorityID,omitempty"`
	Priority     string     `json:"Priority,omitempty"`
	CustomerUser string     `json:"CustomerUser,omitempty"`
	CustomerID   string     `json:"CustomerID,omitempty"`
	Owner        string     `json:"Owner,omitempty"`
	OwnerID      int        `json:"OwnerID,omitempty"`
	Created      TicketTime `json:"Created,omitempty"`
	Changed      TicketTime `json:"Changed,omitempty"`
	Articles     []*Article `json:"Article"`
}

// Create создаёт объект клиента для выполнения запросов
func Create(baseAddr, login, password string) (client *OTRSClient, err error) {
	config.BaseAddress = baseAddr

	client = &OTRSClient{
		Login:    login,
		Password: password,
	}

	if err = client.CreateSession(false); err != nil {
		return
	}

	return
}

// MakeRequest - формирование запроса в OTRS
func (c *OTRSClient) MakeRequest(name string, rawData map[string]interface{}, args ...string) (data []byte, err error) {
	var (
		method   *APIMethod
		url      string
		otrsResp *OTRSErrorResponse
		payload  []byte
	)

	if len(rawData) == 0 {
		err = fmt.Errorf("Пустой запрос")
		return
	}

	method, ok := config.Connector.API[name]
	if !ok {
		err = fmt.Errorf("Неверное имя запроса в OTRS: %s", name)
		return
	}

	if payload, err = json.Marshal(rawData); err != nil {
		return
	}
	body := bytes.NewReader(payload)

	client := &http.Client{Timeout: time.Duration(30) * time.Second}
	if url, err = formURL(method.Route, args...); err != nil {
		return
	}

	req, err := http.NewRequest(method.ReqMethod, url, body)
	if err != nil {
		return
	}

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	data, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return
	}

	// Проверка, не вернулась ли ошибка
	if err = json.Unmarshal(data, &otrsResp); err != nil {
		return
	}
	if otrsResp.Error.ErrorCode != "" {
		// Сессия завершилась, необходимо обновить токен и повторить запрос
		if otrsResp.Error.ErrorCode == "TicketCreate.AuthFail" {
			if err = c.CreateSession(true); err != nil {
				return
			}
			rawData["SessionID"] = c.SessionID
			return c.MakeRequest(name, rawData, args...)
		}
		err = fmt.Errorf("%s: %s", otrsResp.Error.ErrorCode, otrsResp.Error.ErrorMessage)
		return
	}

	return
}

// CreateSession создаёт активную сессию или обновляет токен
func (c *OTRSClient) CreateSession(renew bool) (err error) {
	var data []byte

	if c.Login == "" || c.Password == "" {
		err = fmt.Errorf("Не указан логин/пароль для авторизации в OTRS")
		return
	}

	if renew || c.SessionID == "" {
		if data, err = c.MakeRequest("SessionCreate", map[string]interface{}{
			"UserLogin": c.Login,
			"Password":  c.Password,
		}); err != nil {
			return
		}
		err = json.Unmarshal(data, &c)
	}

	return
}

// TicketSearch возвращает список найденных ID тикетов
// В качестве аргументов можно указывать дополнительно
// https://doc.otrs.com/doc/api/otrs/6.0/Perl/Kernel/System/Ticket/TicketSearch.pm.html
func (c *OTRSClient) TicketSearch(ticket *Ticket, args map[string]interface{}) (ids []string, err error) {
	var (
		data   []byte
		idResp struct {
			IDs []string `json:"TicketID"`
		}
	)

	rawData := map[string]interface{}{
		"SessionID": c.SessionID,
	}

	// Тикет может отсутствовать при поиске в очереди
	if ticket != nil {
		tf := reflect.TypeOf(ticket).Elem()
		vf := reflect.ValueOf(ticket).Elem()
		for i := 0; i < vf.NumField(); i++ {
			fname := tf.Field(i).Name
			if v := reflect.Indirect(vf).FieldByName(fname); !v.IsZero() {
				rawData[fname] = v.Interface()
			}
		}
	}

	// Вносим дополнительные поля
	if args != nil {
		for k, v := range args {
			rawData[k] = v
		}
	}

	if data, err = c.MakeRequest("TicketSearch", rawData); err != nil {
		return
	}

	if err = json.Unmarshal(data, &idResp); err != nil {
		return
	}

	ids = idResp.IDs

	return
}

// TicketByID получает информацию о тикете по ID
// flags - слайс строковых флагов:
// "AllArticles" - получить вместе с информацией о тикете массив связанных сообщений
func (c *OTRSClient) TicketByID(id int, flags []string) (ticket *Ticket, err error) {
	var (
		data   []byte
		idResp struct {
			Tickets []Ticket `json:"Ticket"`
		}
	)

	rawData := map[string]interface{}{
		"SessionID": c.SessionID,
	}

	// Insert additional flags
	if flags != nil {
		for _, flag := range flags {
			rawData[flag] = 1
		}
	}

	if data, err = c.MakeRequest("TicketGet", rawData, strconv.Itoa(id)); err != nil {
		return
	}

	if err = json.Unmarshal(data, &idResp); err != nil {
		return
	}
	ticket = &idResp.Tickets[0]

	return
}

// TicketByNumber получает информацию о тикете по номеру
func (c *OTRSClient) TicketByNumber(number string, flags []string) (ticket *Ticket, err error) {
	ticket = &Ticket{
		TicketNumber: number,
	}

	ids, err := c.TicketSearch(ticket, nil)
	if err != nil {
		return
	}
	if len(ids) == 0 {
		err = fmt.Errorf("Тикет №%s не найден в OTRS", number)
		return
	}

	// Гарантируется уникальность тикета по номеру, берём первый из списка
	id, err := strconv.Atoi(ids[0])
	if err != nil {
		return
	}
	ticket, err = c.TicketByID(id, flags)

	return
}

// TicketCreate создаёт новый тикет в OTRS и заполняет поля TicketID, TicketNumber в случае успеха
func (c *OTRSClient) TicketCreate(ticket *Ticket, article *Article, attachments []*Attachment) (err error) {
	var (
		data []byte
		resp struct {
			TicketID     int    `json:"TicketID,string"`
			TicketNumber string `json:"TicketNumber"`
		}
	)

	ok, err := ticket.Valid()
	if !ok {
		return
	}

	rawData := map[string]interface{}{
		"SessionID":  c.SessionID,
		"Ticket":     ticket,
		"Article":    article,
		"Attachment": attachments,
	}

	if data, err = c.MakeRequest("TicketCreate", rawData); err != nil {
		return
	}
	if err = json.Unmarshal(data, &resp); err != nil {
		return
	}
	ticket.TicketID = resp.TicketID
	ticket.TicketNumber = resp.TicketNumber

	return
}

// TicketUpdate - обновление информации о тикете
func (c *OTRSClient) TicketUpdate(ticket *Ticket, article *Article, attachments []*Attachment) (err error) {
	if ticket.TicketID == 0 {
		err = fmt.Errorf("Необходимо указать TicketID")
		return
	}

	rawData := map[string]interface{}{
		"SessionID":  c.SessionID,
		"Ticket":     ticket,
		"Article":    article,
		"Attachment": attachments,
	}

	if _, err = c.MakeRequest("TicketUpdate", rawData, strconv.Itoa(ticket.TicketID)); err != nil {
		return
	}

	return
}

// Valid - валидация полей в тикете (некоторые поля обязательны, некоторые должны присутствовать парами)
func (t *Ticket) Valid() (valid bool, err error) {
	if t.Title == "" {
		err = fmt.Errorf("Необходимо указать Title")
	}
	if t.Queue == "" && t.QueueID == 0 {
		err = fmt.Errorf("Необходимо указать Queue либо QueueID")
	}
	if t.State == "" && t.StateID == 0 {
		err = fmt.Errorf("Необходимо указать State либо StateID")
	}
	if t.Priority == "" && t.PriorityID == 0 {
		err = fmt.Errorf("Необходимо указать Priority либо PriorityID")
	}
	if t.Type != "" && t.TypeID != 0 {
		err = fmt.Errorf("Необходимо указать либо Type либо TypeID")
	}
	if t.CustomerUser == "" {
		err = fmt.Errorf("Необходимо указать CustomerUser")
	}

	if err == nil {
		valid = true
	}

	return
}

// ArticleCreate формирует объект статьи, заполняя необходимые для запросов поля
func ArticleCreate(a *Article) *Article {
	a.Charset = "UTF8"
	a.MimeType = "text/plain"

	return a
}

// AttachmentCreate создаёт вложение из массива байт
func AttachmentCreate(data []byte, filename string) (att *Attachment, err error) {
	content := base64.StdEncoding.EncodeToString(data)
	contentMime := mimetype.Detect(data)

	att = &Attachment{
		Content:     content,
		ContentType: contentMime.String(),
		Filename:    filename,
	}

	return
}

// AttachmentCreateFromFile создаёт вложение из файла на диске
func AttachmentCreateFromFile(filename string) (att *Attachment, err error) {
	var data []byte

	if data, err = ioutil.ReadFile(filename); err != nil {
		return
	}

	return AttachmentCreate(data, filepath.Base(filename))
}

// QueueInfo - получение ID тикетов в очереди по именам и статусам тикетов
func (c *OTRSClient) QueueInfo(queues, states []string) (ids []string, err error) {
	args := make(map[string]interface{})

	if queues != nil {
		args["Queues"] = queues
	}
	if states != nil {
		args["States"] = states
	}

	if args == nil {
		err = fmt.Errorf("Необходимо указать название очереди или статус тикета")
		return
	}

	ids, err = c.TicketSearch(nil, args)
	if err != nil {
		return
	}

	return
}

// UnmarshalJSON реализует Unmarshaler для кастомного TicketTime
func (t *TicketTime) UnmarshalJSON(b []byte) (err error) {
	rawT, err := time.Parse("2006-01-02 15:04:05", strings.Trim(string(b), "\""))
	if err != nil {
		return
	}
	*t = TicketTime(rawT)

	return
}

// formURL формирует строку запроса с подстановкой аргументов
func formURL(route string, args ...string) (url string, err error) {
	if strings.Contains(route, ":") {
		rawRoute := strings.Split(route, "/:")
		if len(args) != len(rawRoute)-1 {
			err = fmt.Errorf("Неверное количество аргументов в запросе")
			return
		}
		for idx := range args {
			rawRoute[idx+1] = args[idx]
		}
		route = strings.Join(rawRoute, "/")
	}

	url = fmt.Sprintf("%s%s%s%s",
		config.BaseAddress,
		config.BaseURL,
		config.Connector.Name,
		route,
	)

	return
}
