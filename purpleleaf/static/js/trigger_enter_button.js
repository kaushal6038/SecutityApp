// Get the input field
var net_input = document.getElementById("network_input_id");

// Execute a function when the user releases a key on the keyboard
net_input.addEventListener("keyup", function(event) {
  	// Number 13 is the "Enter" key on the keyboard
  	if (event.keyCode === 13) {
    	// Cancel the default action, if needed
    	// event.preventDefault();
    	// Trigger the button element with a click
    	document.getElementById("network_button").click();
  	}
});

// Get the input field
var app_input = document.getElementById("application_url_input_id");

// Execute a function when the user releases a key on the keyboard
app_input.addEventListener("keyup", function(event) {
  	// Number 13 is the "Enter" key on the keyboard
  	if (event.keyCode === 13) {
    	// Cancel the default action, if needed
    	// event.preventDefault();
    	// Trigger the button element with a click
    	document.getElementById("application_button").click();
  	}
});

// Get the input field
var domain_input = document.getElementById("domain_input_id");

// Execute a function when the user releases a key on the keyboard
domain_input.addEventListener("keyup", function(event) {
  	// Number 13 is the "Enter" key on the keyboard
  	if (event.keyCode === 13) {
    	// Cancel the default action, if needed
    	// event.preventDefault();
    	// Trigger the button element with a click
    	document.getElementById("domain_button").click();
  	}
});

// Get the input field
var aws_token_desc_input = document.getElementById("aws_access_token_description_id");

// Execute a function when the user releases a key on the keyboard
aws_token_desc_input.addEventListener("keyup", function(event) {
  	// Number 13 is the "Enter" key on the keyboard
  	if (event.keyCode === 13) {
    	// Cancel the default action, if needed
    	// event.preventDefault();
    	// Trigger the button element with a click
    	document.getElementById("aws_asset_button").click();
  	}
});

// Get the input field
var aws_token_input = document.getElementById("aws_access_token_id");

// Execute a function when the user releases a key on the keyboard
aws_token_input.addEventListener("keyup", function(event) {
  	// Number 13 is the "Enter" key on the keyboard
  	if (event.keyCode === 13) {
    	// Cancel the default action, if needed
    	// event.preventDefault();
    	// Trigger the button element with a click
    	document.getElementById("aws_asset_button").click();
  	}
});

// Get the input field
var aws_secret_input = document.getElementById("aws_secret_token_id");

// Execute a function when the user releases a key on the keyboard
aws_secret_input.addEventListener("keyup", function(event) {
  	// Number 13 is the "Enter" key on the keyboard
  	if (event.keyCode === 13) {
    	// Cancel the default action, if needed
    	// event.preventDefault();
    	// Trigger the button element with a click
    	document.getElementById("aws_asset_button").click();
  	}
});
