package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	"github.com/awnumar/memguard"
	"golang.org/x/crypto/argon2"
)

// SecureEditor structure for the editor
type SecureEditor struct {
	app         fyne.App
	window      fyne.Window
	textArea    *widget.Entry
	currentFile string
	passphrase  *memguard.LockedBuffer
	secureText  *memguard.LockedBuffer
	fileLoaded  bool
	isDarkTheme bool // Track current theme state
}

func main() {
	// Initialize MemGuard and ensure secure cleanup
	memguard.CatchInterrupt()
	defer memguard.Purge()

	// Create Fyne app
	myApp := app.NewWithID("oc2mx.net.seced")
	editor := &SecureEditor{
		app:         myApp,
		isDarkTheme: true, // Start with dark theme
	}

	editor.window = myApp.NewWindow("seced")
	editor.window.Resize(fyne.NewSize(700, 500))

	// Set initial theme
	myApp.Settings().SetTheme(theme.DarkTheme())

	// Create text area
	editor.textArea = widget.NewMultiLineEntry()
	editor.textArea.SetPlaceHolder("Enter text...")
	editor.textArea.Wrapping = fyne.TextWrapWord

	// Set monospace font
	monospace := &fyne.TextStyle{Monospace: true}
	editor.textArea.TextStyle = *monospace

	// Monitor text changes for additional protection
	editor.textArea.OnChanged = editor.onTextChanged

	// Create buttons
	saveButton := widget.NewButton("Save", editor.saveFile)
	loadButton := widget.NewButton("Load", editor.loadFile)
	clearButton := widget.NewButton("Clear", editor.clearEditor)
	encryptButton := widget.NewButton("Encrypt", editor.encryptText)
	decryptButton := widget.NewButton("Decrypt", editor.decryptText)

	// Create theme switch button
	themeSwitch := widget.NewButton("☀️", editor.toggleTheme)
	themeSwitch.Importance = widget.LowImportance

	// Create top bar with theme switch on the right
	topBar := container.NewHBox(
		layout.NewSpacer(),
		themeSwitch,
	)

	// Create layout with buttons centered
	buttons := container.NewHBox(
		layout.NewSpacer(),
		encryptButton,
		decryptButton,
		saveButton,
		loadButton,
		clearButton,
		layout.NewSpacer(),
	)

	// Main content with top bar
	mainContent := container.NewBorder(
		topBar,
		buttons,
		nil,
		nil,
		editor.textArea,
	)

	editor.window.SetContent(mainContent)
	editor.window.SetCloseIntercept(func() {
		editor.cleanup()
		editor.window.Close()
	})
	editor.window.ShowAndRun()
}

// copyToClipboardWithCRLF copies text to clipboard with CRLF line endings
func (e *SecureEditor) copyToClipboardWithCRLF() {
	text := e.textArea.Text
	if text != "" {
		// Convert LF to CRLF for Windows compatibility
		text = strings.ReplaceAll(text, "\n", "\r\n")
		e.window.Clipboard().SetContent(text)
	}
}

// toggleTheme switches between dark and light theme
func (e *SecureEditor) toggleTheme() {
	if e.isDarkTheme {
		e.app.Settings().SetTheme(theme.LightTheme())
		e.isDarkTheme = false
	} else {
		e.app.Settings().SetTheme(theme.DarkTheme())
		e.isDarkTheme = true
	}
	// Refresh the window to apply the new theme
	e.window.Content().Refresh()
}

// pkcs7Pad adds PKCS#7 padding to the data
func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)
	if padding == 0 {
		padding = blockSize
	}
	padded := make([]byte, len(data)+padding)
	copy(padded, data)
	for i := len(data); i < len(padded); i++ {
		padded[i] = byte(padding)
	}
	return padded
}

// pkcs7Unpad removes PKCS#7 padding from the data
func pkcs7Unpad(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("empty data")
	}
	padding := int(data[len(data)-1])
	if padding > len(data) || padding == 0 {
		return nil, errors.New("invalid padding")
	}
	for i := len(data) - padding; i < len(data); i++ {
		if data[i] != byte(padding) {
			return nil, errors.New("invalid padding")
		}
	}
	return data[:len(data)-padding], nil
}

// onTextChanged is called on every text change
func (e *SecureEditor) onTextChanged(newText string) {
	// Securely delete old protected text
	if e.secureText != nil {
		e.secureText.Destroy()
	}

	// Store new text in protected memory
	e.secureText = memguard.NewBufferFromBytes([]byte(newText))
	
	// Automatically copy to clipboard with CRLF
	e.copyToClipboardWithCRLF()
}

// cleanup ensures secure termination
func (e *SecureEditor) cleanup() {
	if e.passphrase != nil {
		e.passphrase.Destroy()
		e.passphrase = nil
	}
	if e.secureText != nil {
		e.secureText.Destroy()
		e.secureText = nil
	}
	e.textArea.SetText("")
	e.fileLoaded = false
}

// clearEditor deletes sensitive data and clears clipboard
func (e *SecureEditor) clearEditor() {
	e.cleanup()
	e.currentFile = ""

	// Clear clipboard
	e.window.Clipboard().SetContent("")

	e.window.SetTitle("seced - Input field and clipboard cleared")
	dialog.ShowInformation("Cleared", "All sensitive data has been removed from memory and clipboard.", e.window)
}

// formatBase64 formats Base64 strings with line breaks after 76 characters
func formatBase64(data string) string {
	var result strings.Builder
	for i, r := range data {
		if i > 0 && i%76 == 0 {
			result.WriteString("\n")
		}
		result.WriteRune(r)
	}
	return result.String()
}

// decodeFormattedBase64 removes line breaks before decoding
func decodeFormattedBase64(data string) ([]byte, error) {
	// Remove all whitespace characters
	cleanData := strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == ' ' || r == '\t' {
			return -1
		}
		return r
	}, data)

	return base64.StdEncoding.DecodeString(cleanData)
}

// askPassword shows a dialog for password entry
func (e *SecureEditor) askPassword(callback func(*memguard.LockedBuffer, error)) {
	password := widget.NewPasswordEntry()
	password.SetMinRowsVisible(1)

	formItems := []*widget.FormItem{
		widget.NewFormItem("Password:", password),
	}

	dlg := dialog.NewForm(
		"Enter password",
		"OK",
		"Cancel",
		formItems,
		func(confirmed bool) {
			if !confirmed {
				callback(nil, errors.New("Password entry cancelled"))
				return
			}

			if len(password.Text) < 12 {
				callback(nil, errors.New("Password must be at least 12 characters long"))
				return
			}

			// Store password in protected memory
			result := memguard.NewBufferFromBytes([]byte(password.Text))
			callback(result, nil)
		},
		e.window,
	)

	dlg.Show()
}

// encryptText encrypts the text and displays it in the text area
func (e *SecureEditor) encryptText() {
	text := e.textArea.Text
	if text == "" {
		dialog.ShowInformation("Info", "No text to encrypt.", e.window)
		return
	}

	// Ask for password
	e.askPassword(func(passphrase *memguard.LockedBuffer, err error) {
		if err != nil {
			dialog.ShowError(err, e.window)
			return
		}

		defer passphrase.Destroy()

		// Perform encryption
		encryptedData, err := e.performEncryption([]byte(text), passphrase)
		if err != nil {
			dialog.ShowError(fmt.Errorf("Encryption failed: %v", err), e.window)
			return
		}

		// Display encrypted text in text area
		e.textArea.SetText(encryptedData)
		// dialog.ShowInformation("Success", "Text encrypted successfully.", e.window)
	})
}

// performEncryption performs the actual encryption
func (e *SecureEditor) performEncryption(textBytes []byte, passphrase *memguard.LockedBuffer) (string, error) {
	// Pad the message using PKCS#7
	paddedText := pkcs7Pad(textBytes, aes.BlockSize)

	textBuffer := memguard.NewBufferFromBytes(paddedText)
	defer textBuffer.Destroy()

	// Generate salt and nonce
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("error generating salt: %v", err)
	}

	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("error generating nonce: %v", err)
	}

	// Derive key with Argon2id
	key := argon2.IDKey(passphrase.Bytes(), salt, 3, 64*1024, 4, 32)

	// Prepare AES-GCM encryption
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("error creating cipher: %v", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("error creating GCM: %v", err)
	}

	// Encrypt text
	ciphertext := aesgcm.Seal(nil, nonce, textBuffer.Bytes(), nil)

	// Prepare encrypted data
	encryptedData := make([]byte, 0, 16+12+len(ciphertext))
	encryptedData = append(encryptedData, salt...)
	encryptedData = append(encryptedData, nonce...)
	encryptedData = append(encryptedData, ciphertext...)

	// Return base64-encoded data
	base64Data := base64.StdEncoding.EncodeToString(encryptedData)
	return formatBase64(base64Data), nil
}

// decryptText decrypts text from the text area
func (e *SecureEditor) decryptText() {
	text := e.textArea.Text
	if text == "" {
		dialog.ShowInformation("Info", "No text to decrypt.", e.window)
		return
	}

	// Ask for password
	e.askPassword(func(passphrase *memguard.LockedBuffer, err error) {
		if err != nil {
			dialog.ShowError(err, e.window)
			return
		}

		defer passphrase.Destroy()

		// Perform decryption
		decryptedText, err := e.performDecryption(text, passphrase)
		if err != nil {
			dialog.ShowError(fmt.Errorf("Decryption failed: %v", err), e.window)
			return
		}

		// Display decrypted text
		e.textArea.SetText(decryptedText)
		// dialog.ShowInformation("Success", "Text decrypted successfully.", e.window)
	})
}

// performDecryption performs the actual decryption
func (e *SecureEditor) performDecryption(encryptedData string, passphrase *memguard.LockedBuffer) (string, error) {
	// Decode base64 data
	encryptedBytes, err := decodeFormattedBase64(encryptedData)
	if err != nil {
		return "", fmt.Errorf("error decoding data: %v", err)
	}

	if len(encryptedBytes) < 28 {
		return "", fmt.Errorf("encrypted data too short or corrupted")
	}

	salt := encryptedBytes[:16]
	nonce := encryptedBytes[16:28]
	ciphertext := encryptedBytes[28:]

	// Derive key with Argon2id
	key := argon2.IDKey(passphrase.Bytes(), salt, 3, 64*1024, 4, 32)

	// Prepare AES-GCM decryption
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("error creating cipher: %v", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("error creating GCM: %v", err)
	}

	// Decrypt text
	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("decryption failed: wrong password?")
	}

	// Remove PKCS#7 padding
	cleanText, err := pkcs7Unpad(plaintext)
	if err != nil {
		return "", fmt.Errorf("error removing padding: %v", err)
	}

	return string(cleanText), nil
}

// hasTextToSave checks if there is text to save
func (e *SecureEditor) hasTextToSave() bool {
	return e.textArea.Text != ""
}

// showSaveDialog shows the save dialog
func (e *SecureEditor) showSaveDialog() {
	// Suggest default filename
	filename := "document.txt"
	if e.currentFile != "" {
		filename = filepath.Base(e.currentFile)
	}

	saveDialog := dialog.NewFileSave(func(uri fyne.URIWriteCloser, err error) {
		if err != nil && isHarmlessError(err) {
			// Simply ignore and continue
		} else if err != nil {
			dialog.ShowError(err, e.window)
			return
		}

		if uri == nil {
			return // User cancelled
		}
		defer uri.Close()

		e.currentFile = uri.URI().Path()
		e.saveFileContent()
	}, e.window)

	saveDialog.SetFileName(filename)
	saveDialog.Show()
}

// isHarmlessError checks if it's a harmless system folder error
func isHarmlessError(err error) bool {
	if err == nil {
		return false
	}

	errorMsg := err.Error()
	return strings.Contains(errorMsg, "VIDEOS folder") ||
		strings.Contains(errorMsg, "MUSIC folder") ||
		strings.Contains(errorMsg, "PICTURES folder") ||
		strings.Contains(errorMsg, "DOCUMENTS folder")
}

// saveFile saves the text as plain text to a file
func (e *SecureEditor) saveFile() {
	if !e.hasTextToSave() {
		dialog.ShowInformation("Info", "No text to save.", e.window)
		return
	}

	e.showSaveDialog()
}

// saveFileContent performs the actual file saving
func (e *SecureEditor) saveFileContent() {
	text := e.textArea.Text
	if text == "" {
		dialog.ShowInformation("Info", "No text to save.", e.window)
		return
	}

	// Convert LF to CRLF for Windows compatibility
	text = strings.ReplaceAll(text, "\n", "\r\n")

	err := os.WriteFile(e.currentFile, []byte(text), 0600)
	if err != nil {
		dialog.ShowError(fmt.Errorf("Error saving file: %v", err), e.window)
		return
	}

	e.window.SetTitle("seced - " + filepath.Base(e.currentFile))
	e.fileLoaded = true
	// dialog.ShowInformation("Success", "Data has been saved.", e.window)
}

// loadFile loads a plain text file
func (e *SecureEditor) loadFile() {
	loadDialog := dialog.NewFileOpen(func(uri fyne.URIReadCloser, err error) {
		if err != nil && isHarmlessError(err) {
			// Simply ignore and continue
		} else if err != nil {
			dialog.ShowError(err, e.window)
			return
		}

		if uri == nil {
			return // User cancelled
		}
		defer uri.Close()

		e.currentFile = uri.URI().Path()
		e.loadFileContent()
	}, e.window)

	loadDialog.Show()
}

// loadFileContent performs the actual file loading
func (e *SecureEditor) loadFileContent() {
	// Read data from file
	content, err := os.ReadFile(e.currentFile)
	if err != nil {
		dialog.ShowError(fmt.Errorf("Error reading file: %v", err), e.window)
		return
	}

	// Convert CRLF to LF for consistent internal handling
	text := strings.ReplaceAll(string(content), "\r\n", "\n")

	// Display text in editor
	e.textArea.SetText(text)

	e.window.SetTitle("seced - " + filepath.Base(e.currentFile))
	e.fileLoaded = true
	// dialog.ShowInformation("Success", "Data has been successfully loaded.", e.window)
}