async function loadItems() {
  const list = document.getElementById("items");
  if (!list) return;

  const res = await fetch("/api/items");
  const items = await res.json();

  list.innerHTML = items.map((item) => `<li>${item.name}</li>`).join("");
}

document.addEventListener("DOMContentLoaded", loadItems);
