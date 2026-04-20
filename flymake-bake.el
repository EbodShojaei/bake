;;; flymake-bake.el --- Flymake backend for Makefiles using mbake  -*- lexical-binding: t; -*-

;; Version: 0.1.0
;; Keywords: languages, tools
;; URL: https://github.com/EbodShojaei/bake
;; Package-Requires: ((emacs "26.1"))

;;; Commentary:

;; Provides a Flymake backend that runs `mbake validate' on the current
;; Makefile buffer and reports diagnostics inline.
;;
;; Note: `mbake validate' does not support --stdin; it requires a real
;; file on disk.  This backend writes the buffer contents to a temporary
;; file, runs validation against it, then cleans up.
;;
;; Requires the mbake Python package to be installed:
;;   pip install mbake
;;
;; Basic setup in your Emacs config:
;;
;;   (require 'flymake-bake)
;;   (flymake-bake-setup)
;;
;; Or to enable it manually in a single buffer:
;;   M-x flymake-bake-load
;;   M-x flymake-mode

;;; Code:

(defgroup flymake-bake nil
  "Flymake backend for Makefiles using mbake."
  :group 'languages
  :link '(url-link "https://github.com/EbodShojaei/bake"))

(defcustom flymake-bake-program "mbake"
  "Name or full path of the mbake executable."
  :group 'flymake-bake
  :type 'string)

(defcustom flymake-bake-program-args '("validate")
  "Arguments passed to mbake before the filename.
The temporary file path is always appended as the final argument."
  :group 'flymake-bake
  :type '(repeat string))

;; mbake validate output format: "<file>:<line>: <message>"
;; The filename portion is the temp file path, so we match on anything
;; up to the first colon to stay flexible.
(defvar flymake-bake--output-regex
  "^[^:\n]+:\\([0-9]+\\): \\(.*\\)"
  "Regexp matching mbake validate diagnostic output.
Group 1 is the line number, group 2 is the message.")

(defvar-local flymake-bake--process nil
  "Current flymake-bake checker process for this buffer.")

(defun flymake-bake--run-checker (report-fn &rest _args)
  "Run `mbake validate' on a temp file and report diagnostics to REPORT-FN."
  ;; Cancel any existing process for this buffer.
  (when (and flymake-bake--process
             (process-live-p flymake-bake--process))
    (kill-process flymake-bake--process))

  (let* ((source-buffer (current-buffer))
         ;; Write buffer to a named temp file so mbake validate can read it.
         ;; Use .mk extension so mbake recognises it as a Makefile.
         (tmp-file (make-temp-file "flymake-bake-" nil ".mk"))
         (command (append (list flymake-bake-program)
                          flymake-bake-program-args
                          (list tmp-file))))
    ;; Populate the temp file with the current buffer contents.
    (write-region (point-min) (point-max) tmp-file nil 'silent)

    (setq flymake-bake--process
          (make-process
           :name "flymake-bake"
           :buffer (generate-new-buffer " *flymake-bake*")
           :command command
           :noquery t
           :connection-type 'pipe
           :sentinel
           (lambda (process _event)
             (when (eq (process-status process) 'exit)
               (unwind-protect
                   (if (buffer-live-p source-buffer)
                       (with-current-buffer (process-buffer process)
                         (goto-char (point-min))
                         (let ((diagnostics nil))
                           (while (re-search-forward
                                   flymake-bake--output-regex nil t)
                             (let* ((line (string-to-number (match-string 1)))
                                    (msg  (match-string 2))
                                    (region (flymake-diag-region
                                             source-buffer line))
                                    (diag (flymake-make-diagnostic
                                           source-buffer
                                           (car region)
                                           (cdr region)
                                           :error
                                           msg)))
                               (push diag diagnostics)))
                           (funcall report-fn diagnostics)))
                     ;; Source buffer was killed before we finished; nothing to do.
                     (funcall report-fn nil))
                 ;; Always clean up, regardless of errors.
                 (ignore-errors (delete-file tmp-file))
                 (kill-buffer (process-buffer process)))))))))

;;;###autoload
(defun flymake-bake-load ()
  "Register the mbake Flymake backend in the current buffer.
Enable `flymake-mode' separately, or use `flymake-bake-setup' to
do both automatically via a hook."
  (interactive)
  (add-hook 'flymake-diagnostic-functions #'flymake-bake--run-checker nil t))

;;;###autoload
(defun flymake-bake-setup ()
  "Enable the mbake Flymake backend in all `makefile-mode' buffers.
Call this in your Emacs init file after loading flymake-bake."
  (add-hook 'makefile-mode-hook
            (lambda ()
              (flymake-bake-load)
              (flymake-mode 1))))

(provide 'flymake-bake)
;;; flymake-bake.el ends here
