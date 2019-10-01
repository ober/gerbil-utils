;; -*- Gerbil -*-
namespace: utils

(def version "0.0.1")
(export main)
(declare (not optimize-dead-definitions))

(import
  :gerbil/gambit
  :gerbil/gambit/ports
  :scheme/base
  :std/crypto/cipher
  :std/crypto/etc
  :std/crypto/libcrypto
  :std/db/dbi
  :std/debug/heap
  :std/iter
  :std/error
  :std/format
  :std/generic
  :std/generic/dispatch
  :std/misc/channel
  :std/misc/list
  :std/misc/ports
  :std/net/address
  :std/net/request
  :std/net/uri
  :std/pregexp
  :std/srfi/1
  :std/srfi/13
  :std/srfi/19
  :std/srfi/95
  :std/sugar
  :std/text/base64
  :std/text/json
  :std/text/utf8
  :std/text/yaml
  :std/text/zlib
  :std/xml/ssax
  )

(import (rename-in :gerbil/gambit/os (current-time builtin-current-time)))
(import (rename-in :gerbil/gambit/os (time mytime)))

(def (dp msg)
  (when DEBUG
    (displayln msg)))

(def (resolve-ipv4 host)
  (if (hash-key? good-ips host)
    (hash-get good-ips host)
    (let* ((host-info (host-info-addresses (host-info host))))
      (dp (format "host-info: ~a type:~a" host-info (type-of host-info)))
      (ip4-address->string
       (car host-info)))))


(def (do-get-generic uri headers)
  (let* ((reply (http-get uri
			  headers: headers))
	 (status (request-status reply))
	 (text (request-text reply)))
    (print-curl "get" uri "" "")
    (if (success? status)
      text
      (displayln (format "Error: got ~a on request. text: ~a~%" status text)))))

(def (usage-verb verb)
  (let ((howto (hash-get interactives verb)))
    (displayln "Wrong number of arguments. Usage is:")
    (displayln program-name " " (hash-get howto usage:))
    (exit 2)))

(def (nth n l)
  (if (or (> n (length l)) (< n 0))
    (error "Index out of bounds.")
    (if (eq? n 0)
      (car l)
      (nth (- n 1) (cdr l)))))

(def (float->int num)
  (inexact->exact
   (round num)))

(def (epoch->date epoch)
  (cond
   ((string? epoch)
    (time-utc->date (make-time time-utc 0 (string->number epoch))))
   ((flonum? epoch)
    (time-utc->date (make-time time-utc 0 (float->int epoch))))
   ((fixnum? epoch)
    (time-utc->date (make-time time-utc 0 epoch)))))

(def (date->epoch mydate)
  (string->number (date->string (string->date mydate "~Y-~m-~d ~H:~M:~S") "~s")))

(def (flatten x)
  (cond ((null? x) [])
	((pair? x) (append (flatten (car x)) (flatten (cdr x))))
	(else [x])))

(def (encrypt-string str)
  (let* ((cipher (make-aes-256-ctr-cipher))
	 (iv (random-bytes (cipher-iv-length cipher)))
	 (key (random-bytes (cipher-key-length cipher)))
	 (encrypted-password (encrypt cipher key iv str))
	 (enc-pass-store (u8vector->base64-string encrypted-password))
	 (iv-store (u8vector->base64-string iv))
	 (key-store (u8vector->base64-string key)))
    (hash
     (key key-store)
     (iv iv-store)
     (password enc-pass-store))))

(def (decrypt-password key iv password)
  (bytes->string
   (decrypt
    (make-aes-256-ctr-cipher)
    (base64-string->u8vector key)
    (base64-string->u8vector iv)
    (base64-string->u8vector password))))

(def (decrypt-bundle bundle)
  (let-hash bundle
    (decrypt-password .key .iv .password)))

(def (find-cookie cookies pattern)
  (let ((cookie-of-interest ""))
    (when (list? cookies)
      (for (c cookies)
      	   (when (pregexp-match pattern c)
      	     (set! cookie-of-interest (car (pregexp-split ";" (cadr (pregexp-split "=" c))))))))
    cookie-of-interest))

(def (strip-^m str)
  (if (string? str)
    (string-trim-both str)
    str))

(def (collect-from-pool threads)
  (when (list? threads)
    (let ((data []))
      (while (> (length threads) 0)
	(let ((running_t 0)
	      (waiting_t 0)
	      (abterminated_t 0)
	      (terminated_t 0))
	  (for (thread threads)
	       (let* ((thread (car threads))
		      (state (thread-state thread)))
		 (cond
		  ((thread-state-running? state) (set! running_t (+ running_t 1)))
		  ((thread-state-waiting? state) (set! waiting_t (+ waiting_t 1)))
		  ((thread-state-abnormally-terminated? state) (set! abterminated_t (+ abterminated_t 1)))
		  ((thread-state-normally-terminated? state) (set! terminated_t (+ terminated_t 1))
		   (let* ((results (thread-state-normally-terminated-result state)))
		     (set! data (cons results data))
		     (set! threads (cdr threads))))
		  (else
		   (displayln "unknown state: " (thread-state thread))
		   (set! threads (cdr threads))))))
	  (dp (format "loop: total: ~a running: ~a waiting: ~a terminated: ~a abnormal_terminated: ~a" (length threads) running_t waiting_t terminated_t abterminated_t))
	  (thread-sleep! 1)))
      data)))

(def (default-headers basic)
  [
   ["Accept" :: "*/*"]
   ["Content-type" :: "application/json"]])

(def (jif lst sep)
  "If we get a list, join it on sep"
  (if (list? lst)
    (string-join lst sep)
    lst))

(def (hash->str h)
  (let ((results []))
    (if (table? h)
      (begin
	(hash-for-each
	 (lambda (k v)
	   (set! results (append results (list (format " ~a->" k) (format "~a   " v)))))
	 h)
	(append-strings results))
      "N/A")))

(def (hash-key-like hsh pat)
  "Search a hash for keys that match a given regexp and return value"
  (when (table? hsh)
    (let ((found #f))
      (hash-map (lambda (k v)
		  (when (pregexp-match pat k)
		    (set! found v))) hsh)
      found)))


(def (do-delete uri headers)
  (let* ((reply (http-delete uri
			  headers: headers))
	 (status (request-status reply))
	 (text (request-text reply)))
    (print-curl "delete" uri "" "")
    (if (success? status)
      text
      (displayln (format "Error: got ~a on request. text: ~a~%" status text)))))

(def (from-json json)
  (try
   (with-input-from-string json read-json)
   (catch (e)
     (displayln "error parsing json " e))))

(def (do-put uri headers data)
  (dp (print-curl "put" uri headers data))
  (let* ((reply (http-put uri
			  headers: headers
			  data: data))
	 (status (request-status reply))
	 (text (request-text reply)))

    (if (success? status)
      (displayln text)
      (displayln (format "Failure on put. Status:~a Text:~a~%" status text)))))

(def (do-post-generic uri headers data)
  (try
   (let* ((reply (http-post uri
			    headers: headers
			    data: data))
	  (status (request-status reply))
	  (text (request-text reply)))
     (dp (print-curl "post" uri headers data))
     (if (success? status)
       text
       (displayln (format "Error: Failure on a post. got ~a text: ~a~%" status text))))
   (catch (e)
     (display-exception e))))


(def (do-post uri headers data)
  (dp (print-curl "post" uri headers data))
  (try
   (let* ((reply (http-post uri
			    headers: headers
			    data: data))
	  (status (request-status reply))
	  (text (request-text reply)))

     (if (success? status)
       text
       (displayln (format "Failure on post. Status:~a Text:~a~%" status text))))
   (catch (e)
     (display-exception e))))

(def (success? status)
  (and (>= status 200) (<= status 299)))

(def (stringify-hash h)
  (let ((results []))
    (if (table? h)
      (begin
	(hash-for-each
	 (lambda (k v)
	   (set! results (append results (list (format " ~a->" k) (format "~a   " v)))))
	 h)
	(append-strings results))
      "N/A")))

(def (remove-bad-matches vars omit)
  (let ((goodies []))
    (for (var vars)
         (unless (string-contains var omit)
           (set! goodies (flatten (cons var goodies)))))
    (reverse goodies)))

(def (interpol str)
  (displayln (interpol-from-env str)))

(def (interpol-from-env str)
  (if (not (string? str))
    str
    (let* ((ruby (pregexp "#\\{([a-zA-Z0-9_-]*)\\}"))
           (vars (remove-bad-matches (match-regexp ruby str) "#"))
           (newstr (pregexp-replace* ruby str "~a"))
           (set-vars []))

      (for (var vars)
           (let ((val (getenv var #f)))
             (if (not val)
               (begin
                 (displayln "Error: Variable " var " is used in the template, but not defined in the environment")
                 (exit 2))
               (set! set-vars (cons val set-vars)))))
      (dp (format "interpol-from-env: string: ~a set-vars: ~a newstr: ~a" str set-vars newstr))
      (apply format newstr set-vars))))

(def (match-regexp pat str . opt-args)
  "Like pregexp-match but for all matches til end of str"
  (let ((n (string-length str))
        (ix-prs []))
    (let lp ((start 0))
      (let* ((pp (pregexp-match-positions pat str start n))
             (ix-pr (pregexp-match pat str start n)))
        (if ix-pr
          (let ((pos (+ 1 (cdar pp))))
            (set! ix-prs (flatten (cons ix-pr ix-prs)))
            (if (< pos n)
              (lp pos)
              ix-prs))
          (reverse ix-prs))))))

(def (error-print msg (code 2))
  (displayln "Error: " msg)
  (exit code))
