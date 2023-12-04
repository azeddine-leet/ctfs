let wordCount = 0;

const intervalId = setInterval(function() {
    // Extract the correct word
    const correctWord = document.querySelector('strong[name="word-title"]').textContent.trim();
    
    // Print the correct word to the console
    console.log(correctWord);

    // Write the correct word into an input field (assuming the input field has the name attribute set to "word")
    const inputElement = document.querySelector('input[name="word"]');
    if (inputElement) {
        inputElement.value = correctWord;

        // Simulate clicking the submit button (assuming the button has the type attribute set to "submit")
        const submitButton = inputElement.closest('form').querySelector('button[type="submit"]');
        if (submitButton) {
            submitButton.click();
        } else {
            console.error("Submit button not found.");
        }
    } else {
        console.error("Input field not found.");
    }

    // Increment word count
    wordCount++;

    // Check if word count reaches 151 and clear the interval
    if (wordCount >= 155) {
        clearInterval(intervalId);
        console.log("Interval cleared after 151 words.");
    }
}, 600);
