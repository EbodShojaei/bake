;;; bake-format.el --- Format Makefiles using mbake  -*- lexical-binding: t; -*-

;; Version: 0.1.0
;; Keywords: languages, tools
;; URL: https://github.com/EbodShojaei/bake
;; Package-Requires: ((emacs "26.1") (reformatter "0.3"))

;;; Commentary:

;; Provides `bake-format-buffer', `bake-format-region', and
;; `bake-format-on-save-mode' for formatting Makefiles via mbake.
;;
;; Requires the mbake Python package to be installed:
;;   pip install mbake
;;
;; Basic setup in your Emacs config:
;;
;;   (require 'bake-format)
;;   (bake-format-setup)
;;
;; This enables on-save formatting in all `makefile-mode' buffers.
;; To enable it manually in a buffer: M-x bake-format-on-save-mode
;; To format once without enabling the mode: M-x bake-format-buffer

;;; Code:

(require 'reformatter)

(defgroup bake-format nil
  "Format Makefiles using the mbake formatter."
  :group 'languages
  :link '(url-link "https://github.com/EbodShojaei/bake"))

(defcustom bake-format-command "mbake"
  "Name or full path of the mbake executable."
  :type 'string
  :group 'bake-format)

(reformatter-define bake-format
  :program bake-format-command
  :args '("format" "--stdin")
  :lighter " BakeFmt"
  :group 'bake-format)

;;;###autoload
(defun bake-format-setup ()
  "Enable `bake-format-on-save-mode' in all `makefile-mode' buffers.
Call this in your Emacs init file after loading bake-format."
  (add-hook 'makefile-mode-hook #'bake-format-on-save-mode))

(provide 'bake-format)
;;; bake-format.el ends here
