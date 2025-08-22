package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/storage"
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
	blockSize   int // Padding block size in bytes
}

// Padding marker to identify padded content
const paddingMarker = "PADDED||"

func main() {
	// Initialize MemGuard and ensure secure cleanup
	memguard.CatchInterrupt()
	defer memguard.Purge()

	// Create Fyne app
	myApp := app.NewWithID("oc2mx.net.seced")
	myApp.Settings().SetTheme(theme.DarkTheme())
	editor := &SecureEditor{
		app:       myApp,
		blockSize: 4096, // Default 4KB block size
	}

	editor.window = myApp.NewWindow("seced")
	editor.window.Resize(fyne.NewSize(700, 500))

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
	saveButton := widget.NewButton("Save", editor.saveText)
	loadButton := widget.NewButton("Load", editor.loadText)
	clearButton := widget.NewButton("Clear", editor.clearEditor)
	paddingButton := widget.NewButton("Padding", editor.showPadding)

	// Create layout with two buttons on each side
	buttons := container.NewHBox(
		paddingButton,
		clearButton,
		layout.NewSpacer(),
		saveButton,
		loadButton,
	)

	content := container.NewBorder(
		nil,
		buttons,
		nil,
		nil,
		editor.textArea,
	)

	editor.window.SetContent(content)
	editor.window.SetCloseIntercept(func() {
		editor.cleanup()
		editor.window.Close()
	})
	editor.window.ShowAndRun()
}

// showPadding shows the settings dialog
func (e *SecureEditor) showPadding() {
	blockSizeEntry := widget.NewEntry()
	blockSizeEntry.SetText(fmt.Sprintf("%d", e.blockSize))
	blockSizeEntry.SetPlaceHolder("Enter block size in bytes (e.g., 4096)")

	formItems := []*widget.FormItem{
		widget.NewFormItem("Block Size:", blockSizeEntry),
	}

	dialog.ShowForm(
		"Settings (bytes)",
		"Save",
		"Cancel",
		formItems,
		func(confirmed bool) {
			if !confirmed {
				return
			}

			newSize, err := strconv.Atoi(blockSizeEntry.Text)
			if err != nil || newSize < 128 {
				dialog.ShowError(errors.New("Invalid block size. Must be at least 128 bytes."), e.window)
				return
			}

			e.blockSize = newSize
			dialog.ShowInformation("Settings Saved", fmt.Sprintf("Block size set to %d bytes", e.blockSize), e.window)
		},
		e.window,
	)
}

// generateRandomUppercase generates random uppercase letters
func generateRandomUppercase(length int) []byte {
	randomBytes := make([]byte, length)
	if _, err := rand.Read(randomBytes); err != nil {
		return make([]byte, length) // Fallback: return empty bytes
	}

	// Convert to uppercase letters (A-Z)
	for i := range randomBytes {
		randomBytes[i] = byte('A' + int(randomBytes[i])%26)
	}
	return randomBytes
}

// padMessage pads the message to the specified block size with random uppercase letters
func (e *SecureEditor) padMessage(message []byte) []byte {
	requiredPadding := e.blockSize - len(message)
	
	if requiredPadding <= len(paddingMarker) {
		// If we can't even fit the marker, don't pad
		return message
	}

	// Create padded message: original + marker + random padding
	padded := make([]byte, e.blockSize)
	copy(padded, message)
	copy(padded[len(message):], paddingMarker)
	
	// Fill remaining space with random uppercase letters
	randomPadding := generateRandomUppercase(requiredPadding - len(paddingMarker))
	copy(padded[len(message)+len(paddingMarker):], randomPadding)
	
	return padded
}

// removePadding removes padding if detected
func removePadding(data []byte) []byte {
	// Convert to string for easier searching
	content := string(data)
	
	// Look for the padding marker
	markerIndex := strings.Index(content, paddingMarker)
	if markerIndex == -1 {
		return data // No padding found, return original data
	}
	
	// Return only the content before the marker
	return data[:markerIndex]
}

// onTextChanged is called on every text change
func (e *SecureEditor) onTextChanged(newText string) {
	// Securely delete old protected text
	if e.secureText != nil {
		e.secureText.Destroy()
	}
	
	// Store new text in protected memory
	e.secureText = memguard.NewBufferFromBytes([]byte(newText))
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

// askPassword shows a dialog for password entry with block size option
func (e *SecureEditor) askPassword(isSave bool, callback func(*memguard.LockedBuffer, error)) {
	password := widget.NewPasswordEntry()
	password.SetMinRowsVisible(1)

	// Add block size option only for save operations
	var formItems []*widget.FormItem
	formItems = append(formItems, widget.NewFormItem("Password:", password))

	if isSave {
		blockSizeInfo := widget.NewLabel(fmt.Sprintf("Current block size: %d bytes", e.blockSize))
		formItems = append(formItems, widget.NewFormItem("", blockSizeInfo))
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

			if len(password.Text) < 8 {
				callback(nil, errors.New("Password must be at least 8 characters long"))
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

// newFile clears the editor and resets the filename
func (e *SecureEditor) newFile() {
	e.cleanup()
	e.window.SetTitle("seced - New file")
}

// hasTextToSave checks if there is text to save
func (e *SecureEditor) hasTextToSave() bool {
	if e.secureText != nil && len(e.secureText.Bytes()) > 0 {
		return true
	}
	return e.textArea.Text != ""
}

// showSaveDialog shows the save dialog
func (e *SecureEditor) showSaveDialog() {
	// Suggest default filename
	filename := "encrypted.bin"
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
		
		// Ask for password with block size info
		e.askPassword(true, func(passphrase *memguard.LockedBuffer, err error) {
			if err != nil {
				dialog.ShowError(err, e.window)
				return
			}
			
			if e.passphrase != nil {
				e.passphrase.Destroy()
			}
			e.passphrase = passphrase
			e.performSave()
		})
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

// saveText saves the text encrypted to a file
func (e *SecureEditor) saveText() {
	if !e.hasTextToSave() {
		dialog.ShowInformation("Info", "No text to save.", e.window)
		return
	}

	e.showSaveDialog()
}

// performSave performs the actual encryption and saving
func (e *SecureEditor) performSave() {
	var text string
	if e.secureText != nil {
		text = string(e.secureText.Bytes())
	} else {
		text = e.textArea.Text
	}
	
	if text == "" {
		dialog.ShowInformation("Info", "No text to save.", e.window)
		return
	}

	textBytes := []byte(text)
	
	// Calculate required padding
	requiredBlocks := int(math.Ceil(float64(len(textBytes)+len(paddingMarker)) / float64(e.blockSize)))
	targetSize := requiredBlocks * e.blockSize
	
	// Temporarily adjust block size for this operation if needed
	originalBlockSize := e.blockSize
	if targetSize > e.blockSize {
		e.blockSize = targetSize
	}
	
	// Pad the message
	paddedText := e.padMessage(textBytes)
	
	var textBuffer *memguard.LockedBuffer
	if e.secureText != nil {
		// Create new buffer with padded data
		textBuffer = memguard.NewBufferFromBytes(paddedText)
		defer textBuffer.Destroy()
	} else {
		textBuffer = memguard.NewBufferFromBytes(paddedText)
		defer textBuffer.Destroy()
	}

	// Generate salt and nonce
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		dialog.ShowError(fmt.Errorf("Error generating salt: %v", err), e.window)
		e.blockSize = originalBlockSize // Restore original block size
		return
	}

	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		dialog.ShowError(fmt.Errorf("Error generating nonce: %v", err), e.window)
		e.blockSize = originalBlockSize // Restore original block size
		return
	}

	// Derive key with Argon2id
	key := argon2.IDKey(e.passphrase.Bytes(), salt, 3, 64*1024, 4, 32)

	// Prepare AES-GCM encryption
	block, err := aes.NewCipher(key)
	if err != nil {
		dialog.ShowError(fmt.Errorf("Error creating cipher: %v", err), e.window)
		e.blockSize = originalBlockSize // Restore original block size
		return
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		dialog.ShowError(fmt.Errorf("Error creating GCM: %v", err), e.window)
		e.blockSize = originalBlockSize // Restore original block size
		return
	}

	// Encrypt text
	ciphertext := aesgcm.Seal(nil, nonce, textBuffer.Bytes(), nil)

	// Save encrypted data in binary format
	encryptedData := make([]byte, 0, 16+12+len(ciphertext))
	encryptedData = append(encryptedData, salt...)
	encryptedData = append(encryptedData, nonce...)
	encryptedData = append(encryptedData, ciphertext...)

	// Save base64-encoded data to file
	base64Data := base64.StdEncoding.EncodeToString(encryptedData)
	formattedBase64 := formatBase64(base64Data)
	
	err = os.WriteFile(e.currentFile, []byte(formattedBase64), 0600)
	if err != nil {
		dialog.ShowError(fmt.Errorf("Error saving file: %v", err), e.window)
		e.blockSize = originalBlockSize // Restore original block size
		return
	}

	// Restore original block size if it was temporarily adjusted
	e.blockSize = originalBlockSize

	e.window.SetTitle("seced - " + filepath.Base(e.currentFile))
	e.fileLoaded = true
	dialog.ShowInformation("Success", "Text has been securely saved.", e.window)
}

// loadText loads an encrypted file and decrypts it
func (e *SecureEditor) loadText() {
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
		
		// Ask for password for decryption
		e.askPassword(false, func(passphrase *memguard.LockedBuffer, err error) {
			if err != nil {
				dialog.ShowError(err, e.window)
				return
			}

			if e.passphrase != nil {
				e.passphrase.Destroy()
			}
			e.passphrase = passphrase
			e.performLoad()
		})
	}, e.window)
	
	fileFilter := storage.NewExtensionFileFilter([]string{".bin", ".enc"})
	loadDialog.SetFilter(fileFilter)
	loadDialog.Show()
}

// performLoad performs the loading and decryption
func (e *SecureEditor) performLoad() {
	// Read base64-encoded data from file
	base64Data, err := os.ReadFile(e.currentFile)
	if err != nil {
		dialog.ShowError(fmt.Errorf("Error reading file: %v", err), e.window)
		return
	}

	// Decode base64 data
	encryptedData, err := decodeFormattedBase64(string(base64Data))
	if err != nil {
		dialog.ShowError(fmt.Errorf("Error decoding data: %v", err), e.window)
		return
	}

	if len(encryptedData) < 28 {
		dialog.ShowError(fmt.Errorf("File too short or corrupted"), e.window)
		return
	}

	salt := encryptedData[:16]
	nonce := encryptedData[16:28]
	ciphertext := encryptedData[28:]

	// Derive key with Argon2id
	key := argon2.IDKey(e.passphrase.Bytes(), salt, 3, 64*1024, 4, 32)

	// Prepare AES-GCM decryption
	block, err := aes.NewCipher(key)
	if err != nil {
		dialog.ShowError(fmt.Errorf("Error creating cipher: %v", err), e.window)
		return
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		dialog.ShowError(fmt.Errorf("Error creating GCM: %v", err), e.window)
		return
	}

	// Decrypt text
	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		dialog.ShowError(fmt.Errorf("Decryption failed: Wrong password?"), e.window)
		return
	}

	// Remove padding if present
	cleanText := removePadding(plaintext)

	// Process decrypted text in a secured environment
	if e.secureText != nil {
		e.secureText.Destroy()
	}
	e.secureText = memguard.NewBufferFromBytes(cleanText)

	// Display text in editor
	e.textArea.SetText(string(e.secureText.Bytes()))

	e.window.SetTitle("seced - " + filepath.Base(e.currentFile))
	e.fileLoaded = true
	dialog.ShowInformation("Success", "Text has been successfully loaded.", e.window)
}