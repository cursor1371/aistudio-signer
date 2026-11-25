package transport

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	fhttp "github.com/Mag1cFall/fhttp"
	quic "github.com/Mag1cFall/uquic"
	"github.com/Mag1cFall/uquic/quicvarint"
)

// h3RequestFields 按 Firefox 的 HTTP/3 请求头生成 QPACK 字段，altUsed 时写入 Alt-Used
func h3RequestFields(request *fhttp.Request, altUsed bool) []qpackField {
	authority := request.Host
	if authority == "" {
		authority = request.URL.Host
	}
	fields := []qpackField{
		{":method", request.Method},
		{":scheme", request.URL.Scheme},
		{":authority", authority},
		{":path", request.URL.RequestURI()},
	}
	header := request.Header.Clone()
	delete(header, fhttp.HeaderOrderKey)
	if altUsed && header.Get("Sec-Fetch-Dest") != "image" {
		header.Set("Alt-Used", request.URL.Hostname())
	}
	if length := request.ContentLength; length > 0 || (length == 0 && (request.Method == "POST" || request.Method == "PUT" || request.Method == "PATCH")) {
		header.Set("Content-Length", strconv.FormatInt(length, 10))
	}
	for _, name := range orderedHeaderNames(header, request.URL.Host) {
		if _, excluded := h3ExcludedRequestHeaders[name]; excluded {
			continue
		}
		values := header.Values(name)
		if len(values) == 0 {
			continue
		}
		separator := ", "
		if name == "cookie" {
			separator = "; "
		}
		fields = append(fields, qpackField{name, strings.Join(values, separator)})
	}
	return fields
}

// roundTrip 在本连接上发送请求并返回响应头已到达的响应，opened 表示请求流已经打开；0-RTT 被拒绝的请求在握手完成后重发一次
func (conn *http3Conn) roundTrip(request *fhttp.Request, fields []qpackField) (*fhttp.Response, bool, error) {
	if !firefoxSafeMethods[request.Method] {
		if err := conn.awaitReady(request.Context()); err != nil {
			return nil, false, err
		}
	}
	response, opened, err := conn.exchange(request, fields)
	if errors.Is(err, quic.Err0RTTRejected) && firefoxSafeMethods[request.Method] {
		if err := conn.awaitReady(request.Context()); err != nil {
			return nil, false, err
		}
		return conn.exchange(request, fields)
	}
	return response, opened, err
}

// exchange 打开请求流写出请求并读取响应头，0-RTT 被拒绝的请求流随 0-RTT 数据一起作废，不再重置
func (conn *http3Conn) exchange(request *fhttp.Request, fields []qpackField) (*fhttp.Response, bool, error) {
	// One context covers header writes, QPACK waits and response reads. QUIC
	// connection loss must also wake a request with no caller deadline.
	ctx, cancel := context.WithCancelCause(request.Context())
	stopConnection := context.AfterFunc(conn.quic.Context(), func() {
		cancel(context.Cause(conn.quic.Context()))
	})
	cleanup := func() {
		stopConnection()
		cancel(context.Canceled)
	}
	if err := conn.decoderMu.LockContext(ctx); err != nil {
		cleanup()
		return nil, false, err
	}
	decoder := conn.decoder
	conn.decoderMu.Unlock()
	stream, err := conn.quic.OpenStreamSync(ctx)
	if err != nil {
		cleanup()
		return nil, false, err
	}
	conn.streams.Add(1)
	body := &http3Body{
		conn: conn, decoder: decoder, stream: stream, reader: bufio.NewReader(stream),
		ctx: ctx, cancel: cancel, stopConnection: stopConnection, source: request.Body,
		uploadDone: make(chan struct{}),
	}
	// Install before taking the encoder lock or writing any request bytes.
	body.stopWatch = context.AfterFunc(ctx, body.abort)
	var response *fhttp.Response
	if err = conn.mu.LockContext(ctx); err == nil {
		block := conn.encoder.encode(fields, int64(stream.StreamID()))
		err = conn.flushEncoderLocked(ctx)
		conn.mu.Unlock()
		if err == nil {
			var n int
			header := appendH3Frame(nil, h3FrameHeaders, block)
			n, err = stream.Write(header)
			if err == nil && n != len(header) {
				err = io.ErrShortWrite
			}
		}
	}
	if err == nil && request.Body != nil && request.Body != fhttp.NoBody {
		go body.writeRequest(request.Body, request.ContentLength)
	} else {
		if err == nil {
			err = body.finishUpload()
		}
		// 没有启动上传协程，包括请求头写入失败的路径。
		close(body.uploadDone)
	}
	if err == nil {
		response, err = body.readResponse(ctx, request)
	}
	if err != nil {
		cause := context.Cause(ctx)
		body.releaseWatch()
		if !errors.Is(err, quic.Err0RTTRejected) {
			body.abort()
		} else {
			body.closeSource()
		}
		<-body.uploadDone
		if cause != nil {
			err = cause
		}
		return nil, true, err
	}
	return response, true, nil
}

// http3Body 是请求流上的响应体，按帧读取 DATA，结尾的 HEADERS 写入 trailer
type http3Body struct {
	conn      *http3Conn
	decoder   *qpackDecoder
	stream    *quic.Stream
	reader    *bufio.Reader
	response  *fhttp.Response
	remaining uint64
	done           atomic.Bool
	aborted        atomic.Bool
	ctx            context.Context
	cancel         context.CancelCauseFunc
	stopWatch      func() bool
	stopConnection func() bool

	source     io.ReadCloser
	sourceOnce sync.Once

	// uploadOnce 互斥正常 FIN 与取消；uploadDone 确认上传协程已经退出。
	uploadOnce sync.Once
	uploadDone chan struct{}
}

// h3DataHeaderMax 是 DATA 帧头的最大长度：1 字节帧类型与 4 字节帧长
const h3DataHeaderMax = 5

// writeRequest 把 source 每次读到的正文写成一个 DATA 帧：读取缓冲前预留帧头的位置，帧头紧贴正文写入后以一次 Write 发出整帧；length 为已知的正文长度，小于每帧上限时缓冲只取这么长
func (body *http3Body) writeRequest(source io.ReadCloser, length int64) {
	defer close(body.uploadDone)
	defer body.closeSource()
	size := h3RequestBodyChunk
	if length > 0 && length < int64(size) {
		size = int(length)
	}
	buffer := make([]byte, h3DataHeaderMax+size)
	for {
		if body.done.Load() || body.ctx.Err() != nil {
			return
		}
		read, err := source.Read(buffer[h3DataHeaderMax:])
		if body.done.Load() || body.ctx.Err() != nil {
			return
		}
		if read > 0 {
			start := h3DataHeaderMax - quicvarint.Len(h3FrameData) - quicvarint.Len(uint64(read))
			quicvarint.Append(quicvarint.Append(buffer[start:start], h3FrameData), uint64(read))
			frame := buffer[start : h3DataHeaderMax+read]
			written, writeErr := body.stream.Write(frame)
			if writeErr == nil && written != len(frame) {
				writeErr = io.ErrShortWrite
			}
			if writeErr != nil {
				body.uploadError(writeErr)
				return
			}
		}
		if err == io.EOF {
			if err := body.finishUpload(); err != nil {
				body.uploadError(err)
			}
			return
		}
		if err != nil {
			body.uploadError(err)
			return
		}
	}
}

// finishUpload 只能在没有并发 Write 时调用。FIN 与 CancelWrite 互斥，
// 避免响应结束后的清理重置已正常提交的上传数据。
func (body *http3Body) finishUpload() (err error) {
	body.uploadOnce.Do(func() {
		err = body.stream.Close()
		if err != nil {
			body.stream.CancelWrite(h3RequestCancelled)
		}
	})
	return err
}

// stopUpload 不等待上传协程，可用于该协程自己的错误路径和 context 回调。
// CancelWrite 解除流写入；请求 Body 按 HTTP 契约支持并发 Close 解除 Read。
// 调用方在收尾路径等待 uploadDone，避免遗留上传任务。
func (body *http3Body) stopUpload() {
	body.uploadOnce.Do(func() { body.stream.CancelWrite(h3RequestCancelled) })
	body.closeSource()
}

func (body *http3Body) uploadError(err error) {
	// 提前完成响应时主动停止上传，不将由此产生的错误改写为响应失败。
	if body.done.Load() || body.aborted.Load() {
		return
	}
	body.cancel(err)
	body.abort()
}

func (body *http3Body) readResponse(ctx context.Context, request *fhttp.Request) (*fhttp.Response, error) {
	for {
		kind, payload, err := readH3Frame(body.reader)
		if err != nil {
			return nil, err
		}
		if kind != h3FrameHeaders {
			if kind == h3FrameData {
				return nil, fmt.Errorf("HTTP/3 响应在 HEADERS 之前收到 DATA")
			}
			continue
		}
		fields, err := body.decoder.decode(ctx, payload, int64(body.stream.StreamID()))
		if err != nil {
			return nil, err
		}
		if err := body.conn.flushDecoder(ctx); err != nil {
			return nil, err
		}
		header := make(fhttp.Header, len(fields))
		status := 0
		for _, field := range fields {
			if field.name == ":status" {
				status, _ = strconv.Atoi(field.value)
				continue
			}
			header.Add(field.name, field.value)
		}
		if status < 100 || status > 599 {
			return nil, fmt.Errorf("HTTP/3 响应状态 %d 无效", status)
		}
		if status < 200 {
			continue
		}
		response := &fhttp.Response{
			Status:        strconv.Itoa(status) + " " + fhttp.StatusText(status),
			StatusCode:    status,
			Proto:         "HTTP/3.0",
			ProtoMajor:    3,
			Header:        header,
			ContentLength: -1,
			Trailer:       fhttp.Header{},
			Request:       request,
			Body:          body,
		}
		if length, err := strconv.ParseInt(header.Get("Content-Length"), 10, 64); err == nil {
			response.ContentLength = length
		}
		body.response = response
		if request.Method != "HEAD" {
			response.Body = fhttp.DecompressBody(response)
		}
		return response, nil
	}
}

func (body *http3Body) Read(buffer []byte) (int, error) {
	for {
		if body.done.Load() {
			return 0, io.EOF
		}
		if len(buffer) == 0 {
			return 0, nil
		}
		if body.remaining > 0 {
			read, err := body.reader.Read(buffer[:min(uint64(len(buffer)), body.remaining)])
			body.remaining -= uint64(read)
			if err == io.EOF {
				err = nil
				if body.remaining > 0 {
					err = io.ErrUnexpectedEOF
				}
			}
			return read, body.readError(err)
		}
		kind, length, err := readH3FrameHeader(body.reader)
		if err == io.EOF {
			if cause := context.Cause(body.ctx); cause != nil {
				return 0, cause
			}
			body.done.Store(true)
			body.stopUpload()
			body.releaseWatch()
			<-body.uploadDone
			return 0, io.EOF
		}
		if err != nil {
			return 0, body.readError(err)
		}
		switch kind {
		case h3FrameData:
			body.remaining = length
		case h3FrameHeaders:
			if length > 16<<20 {
				return 0, fmt.Errorf("HTTP/3 trailer 超出长度上限")
			}
			payload := make([]byte, length)
			if _, err := io.ReadFull(body.reader, payload); err != nil {
				if err == io.EOF {
					err = io.ErrUnexpectedEOF
				}
				return 0, body.readError(err)
			}
			fields, err := body.decoder.decode(body.ctx, payload, int64(body.stream.StreamID()))
			if err != nil {
				return 0, err
			}
			if err := body.conn.flushDecoder(body.ctx); err != nil {
				return 0, body.readError(err)
			}
			for _, field := range fields {
				body.response.Trailer.Add(field.name, field.value)
			}
		default:
			if _, err := io.CopyN(io.Discard, body.reader, int64(length)); err != nil {
				if err == io.EOF {
					err = io.ErrUnexpectedEOF
				}
				return 0, body.readError(err)
			}
		}
	}
}

func (body *http3Body) readError(err error) error {
	if err != nil && body.aborted.Load() {
		if cause := context.Cause(body.ctx); cause != nil {
			return cause
		}
		return errors.New("HTTP/3 响应体已关闭")
	}
	return err
}

func (body *http3Body) releaseWatch() {
	body.stopWatch()
	body.stopConnection()
	body.cancel(context.Canceled)
}

func (body *http3Body) closeSource() {
	body.sourceOnce.Do(func() {
		if body.source != nil {
			_ = body.source.Close()
		}
	})
}

func (body *http3Body) Close() error {
	body.abort()
	body.stopUpload()
	body.releaseWatch()
	<-body.uploadDone
	return nil
}

// abort 按 Firefox 取消未完成响应；响应已到 EOF 时只回收尚未结束的上传。
func (body *http3Body) abort() {
	if body.done.Load() {
		body.stopUpload()
		return
	}
	if !body.aborted.CompareAndSwap(false, true) {
		return
	}
	body.cancel(context.Canceled)
	body.stream.CancelRead(h3RequestCancelled)
	body.stopUpload()
	body.decoder.cancel(int64(body.stream.StreamID()))
	// Cancellation must never wait for a shared decoder-stream write.
	body.conn.scheduleDecoderFlush()
}
