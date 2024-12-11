function removeElement(button, symbol) {
    var row = button.parentElement.parentElement;
    row.remove();

    fetch('/remove_stock', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: 'symbol=' + encodeURIComponent(symbol)
    });

    if (document.getElementsByTagName("tr").length == 1) {
        document.getElementById("thisTable").style.visibility = "hidden";
    }
}


function redirectBuy(button, symbol) {
    fetch('/buy', { method: 'GET' }).then(
        response => {
            const url = new URL(response.url);
            url.searchParams.set('symbol', symbol);
            window.location = url.toString();
        }
    )
}

function redirectSell(button, symbol) {
    fetch("/sell", { method: 'GET' }).then(response => {
        const url = new URL(response.url);
        url.searchParams.set('symbol', symbol);
        window.location = url.toString();
    })
}

function autofocus() {
    var symbol = new URL(window.location.href).searchParams.get("symbol");
    if (symbol && symbol !== "") {
        document.getElementById("secondary").focus();
    }
}
