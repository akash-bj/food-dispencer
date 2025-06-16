document.getElementById("register-form").addEventListener("submit", async function (event) {
    event.preventDefault();

    let username = document.getElementById("register-username").value.trim();
    let password = document.getElementById("register-password").value.trim();
    let confirmPassword = document.getElementById("confirm-password").value.trim();
    let errorElement = document.getElementById("register-error");

    // Validate passwords
    if (password !== confirmPassword) {
        errorElement.textContent = "Passwords do not match.";
        return;
    }

    try {
        // Send registration data to the server
        let response = await fetch("/register", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ username, password, confirm_password: confirmPassword })
        });

        console.log("Response Status:", response.status);

        let result = await response.json();
        console.log("Response Data:", result);

        if (response.ok) {
            alert(result.message);
            window.location.href = "/login"; // Redirect to login page
        } else {
            errorElement.textContent = result.error || "Registration failed.";
        }
    } catch (error) {
        console.error("Fetch Error:", error);
        errorElement.textContent = "An error occurred. Please try again.";
    }
});