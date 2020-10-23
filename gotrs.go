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
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gabriel-vasile/mimetype"
)

var (
	config = &Config{
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

	regAuthFail = regexp.MustCompile("^.*AuthFail.*$")
)

// APIMethod - объект запроса на API OTRS
type APIMethod struct {
	ReqMethod string `yaml:"req_method"`
	Route     string `yaml:"route"`
	Result    string `yaml:"result"`
	Login     bool   `yaml:"login"`
}

// ErrorResponse - ответ OTRS на запрос с ошибкой
type ErrorResponse struct {
	Error struct {
		ErrorMessage string
		ErrorCode    string
	}
}

// TicketConnector - набор методов API OTRS
type TicketConnector struct {
	Name string
	API  map[string]*APIMethod
}

// Config - базовый конфиг настройки запросов в OTRS
type Config struct {
	BaseAddress string
	BaseURL     string
	Connector   TicketConnector
}

// Client - клиент для работы с API сервиса OTRS
type Client struct {
	Login     string `json:"UserLogin"`
	Password  string
	SessionID string
}

// Article - объект статьи в тикете
type Article struct {
	From     string
	To       string
	CC       string
	Subject  string
	Body     string
	Charset  string
	MimeType string
	Created  int64 `json:"IncomingTime"`
	TimeUnit int64
	Type     string `json:"ArticleType"`
}

// Field - объект динамического поля в тикете
type Field struct {
	Name        string
	Value       interface{}
	SearchValue string
}

// Attachment - объект прикрепляемого файла - вложения
type Attachment struct {
	Content     string
	ContentType string
	Filename    string
}

// Ticket - основной объект тикета
type Ticket struct {
	TicketID     int
	TicketNumber string
	Title        string
	QueueID      int
	Queue        string
	TypeID       int
	Type         string
	StateID      int
	State        string
	PriorityID   int
	Priority     string
	CustomerUser string
	CustomerID   string
	Owner        string
	OwnerID      int
	Created      string
	Changed      string
	Articles     []*Article `json:"Article"`
	Fields       []*Field   `json:"DynamicField"`
}

// Request - объект запроса к OTRS
type Request struct {
	SessionID   string
	Ticket      *Ticket
	Article     *Article
	Attachments []*Attachment `json:"Attachment"`
	Fields      []*Field      `json:"DynamicField"`
}

// RequestOption дополняет объект запроса параметром
type RequestOption func(r *Request)

// Create создаёт объект клиента для выполнения запросов
func Create(baseAddr, login, password string) (client *Client, err error) {
	config.BaseAddress = baseAddr

	client = &Client{
		Login:    login,
		Password: password,
	}

	if err = client.CreateSession(false); err != nil {
		return
	}

	return
}

// makeRequest - формирование запроса в OTRS
// Использует объект запроса Request при создании/обновлении тикета и набор флагов map[string]interface{} при получении информации о тикете
func (c *Client) makeRequest(name string, request *Request, rawData map[string]interface{}, args ...string) (data []byte, err error) {
	var (
		method   *APIMethod
		url      string
		otrsResp *ErrorResponse
		payload  []byte
	)

	if request == nil && len(rawData) == 0 {
		err = fmt.Errorf("пустой запрос")
		return
	}

	method, ok := config.Connector.API[name]
	if !ok {
		err = fmt.Errorf("неверное имя запроса в OTRS: %s", name)
		return
	}

	if request != nil {
		payload, err = json.Marshal(request)
	} else {
		payload, err = json.Marshal(rawData)
	}
	if err != nil {
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
		if regAuthFail.MatchString(otrsResp.Error.ErrorCode) {
			if err = c.CreateSession(true); err != nil {
				return
			}
			if request != nil {
				request.SessionID = c.SessionID
			} else {
				rawData["SessionID"] = c.SessionID
			}
			return c.makeRequest(name, request, rawData, args...)
		}
		err = fmt.Errorf("%s: %s", otrsResp.Error.ErrorCode, otrsResp.Error.ErrorMessage)
		return
	}

	return
}

// CreateSession создаёт активную сессию или обновляет токен
func (c *Client) CreateSession(renew bool) (err error) {
	var data []byte

	if c.Login == "" || c.Password == "" {
		err = fmt.Errorf("не указан логин/пароль для авторизации в OTRS")
		return
	}

	if renew || c.SessionID == "" {
		if data, err = c.makeRequest("SessionCreate", nil, map[string]interface{}{
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
func (c *Client) TicketSearch(ticket *Ticket, args map[string]interface{}) (ids []string, err error) {
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

	if data, err = c.makeRequest("TicketSearch", nil, rawData); err != nil {
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
func (c *Client) TicketByID(id int, flags ...string) (ticket *Ticket, err error) {
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

	if data, err = c.makeRequest("TicketGet", nil, rawData, strconv.Itoa(id)); err != nil {
		return
	}

	if err = json.Unmarshal(data, &idResp); err != nil {
		return
	}
	ticket = &idResp.Tickets[0]

	return
}

// TicketByNumber получает информацию о тикете по номеру
func (c *Client) TicketByNumber(number string, flags ...string) (ticket *Ticket, err error) {
	ticket = &Ticket{
		TicketNumber: number,
	}

	ids, err := c.TicketSearch(ticket, nil)
	if err != nil {
		return
	}
	if len(ids) == 0 {
		err = fmt.Errorf("тикет №%s не найден в OTRS", number)
		return
	}

	// Гарантируется уникальность тикета по номеру, берём первый из списка
	id, err := strconv.Atoi(ids[0])
	if err != nil {
		return
	}
	ticket, err = c.TicketByID(id, flags...)

	return
}

// WithAttachments добавляет к запросу прикреплённые файлы
func WithAttachments(attachments ...*Attachment) RequestOption {
	return func(r *Request) {
		r.Attachments = attachments
	}
}

// WithFields добавляет к запросу динамические поля
func WithFields(fields ...*Field) RequestOption {
	return func(r *Request) {
		r.Fields = fields
	}
}

// TicketCreate создаёт новый тикет в OTRS и заполняет поля TicketID, TicketNumber в случае успеха.
// Параметры Ticket, Article являются обязательными, остальные, типа Attachment, DynamicField - опциональными
func (c *Client) TicketCreate(ticket *Ticket, article *Article, opts ...RequestOption) (err error) {
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

	req := &Request{
		SessionID: c.SessionID,
		Ticket:    ticket,
		Article:   article,
	}
	for i := range opts {
		opts[i](req)
	}

	if data, err = c.makeRequest("TicketCreate", req, nil); err != nil {
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
func (c *Client) TicketUpdate(ticket *Ticket, article *Article, opts ...RequestOption) (err error) {
	if ticket.TicketID == 0 {
		err = fmt.Errorf("необходимо указать TicketID")
		return
	}

	req := &Request{
		SessionID: c.SessionID,
		Ticket:    ticket,
		Article:   article,
	}
	for i := range opts {
		opts[i](req)
	}

	if _, err = c.makeRequest("TicketUpdate", req, nil, strconv.Itoa(ticket.TicketID)); err != nil {
		return
	}

	return
}

// Valid - валидация полей в тикете (некоторые поля обязательны, некоторые должны присутствовать парами)
func (t *Ticket) Valid() (valid bool, err error) {
	if t.Title == "" {
		err = fmt.Errorf("необходимо указать Title")
	}
	if t.Queue == "" && t.QueueID == 0 {
		err = fmt.Errorf("необходимо указать Queue либо QueueID")
	}
	if t.State == "" && t.StateID == 0 {
		err = fmt.Errorf("необходимо указать State либо StateID")
	}
	if t.Priority == "" && t.PriorityID == 0 {
		err = fmt.Errorf("необходимо указать Priority либо PriorityID")
	}
	if t.Type != "" && t.TypeID != 0 {
		err = fmt.Errorf("необходимо указать либо Type либо TypeID")
	}
	if t.CustomerUser == "" {
		err = fmt.Errorf("необходимо указать CustomerUser")
	}

	if err == nil {
		valid = true
	}

	return
}

// ArticleCreate формирует объект статьи, заполняя необходимые для запросов поля
func ArticleCreate(a *Article) *Article {
	a.Charset = "UTF8"
	if a.MimeType == "" {
		a.MimeType = "text/plain"
	}

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
func (c *Client) QueueInfo(queues, states []string) (ids []string, err error) {
	args := make(map[string]interface{})

	if queues != nil {
		args["Queues"] = queues
	}
	if states != nil {
		args["States"] = states
	}

	if len(args) == 0 {
		err = fmt.Errorf("необходимо указать название очереди или статус тикета")
		return
	}

	ids, err = c.TicketSearch(nil, args)
	if err != nil {
		return
	}

	return
}

// formURL формирует строку запроса с подстановкой аргументов
func formURL(route string, args ...string) (url string, err error) {
	if strings.Contains(route, ":") {
		rawRoute := strings.Split(route, "/:")
		if len(args) != len(rawRoute)-1 {
			err = fmt.Errorf("неверное количество аргументов в запросе")
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
