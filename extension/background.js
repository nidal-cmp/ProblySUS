// background.js

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "analyze_url") {
        const targetUrl = request.url;
        // URL for the local backend server running on port 5000
        const apiUrl = "http://127.0.0.1:5000/analyze";

        fetch(apiUrl, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ url: targetUrl })
        })
            .then(response => {
                if (!response.ok) {
                    return response.json().then(errData => {
                        throw new Error(errData.error || `HTTP error! status: ${response.status}`);
                    }).catch(() => {
                        throw new Error(`HTTP error! status: ${response.status}`);
                    });
                }
                return response.json();
            })
            .then(data => {
                sendResponse({ data: data });
            })
            .catch(error => {
                console.error("Error connecting to backend:", error);
                sendResponse({ error: error.message || "Failed to connect to ProblySUS API. Is the local server running?" });
            });

        // Return true to indicate we will send a response asynchronously
        return true;
    }
});
