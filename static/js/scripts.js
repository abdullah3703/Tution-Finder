document.addEventListener('DOMContentLoaded', function () {
    const body = document.getElementById('body');
    const toggleButton = document.getElementById('darkModeToggle');

    function setDarkMode(enabled) {
        if (enabled) {
            body.classList.add('dark-mode');
            toggleButton.textContent = '☀️'; // Light mode icon
            localStorage.setItem('darkMode', 'enabled');
        } else {
            body.classList.remove('dark-mode');
            toggleButton.textContent = '🌙'; // Dark mode icon
            localStorage.setItem('darkMode', 'disabled');
        }
    }

    // Load saved preference
    const saved = localStorage.getItem('darkMode') === 'enabled';
    setDarkMode(saved);

    toggleButton.addEventListener('click', () => {
        const isDark = body.classList.contains('dark-mode');
        setDarkMode(!isDark);
    });
});
document.addEventListener('DOMContentLoaded', function () {
    const divisionSelect = document.getElementById('division');
    const districtSelect = document.getElementById('district');
    const upazilaSelect = document.getElementById('upazila');

    divisionSelect?.addEventListener('change', function () {
        fetch(`/districts/${this.value}`)
            .then(res => res.json())
            .then(data => {
                districtSelect.innerHTML = '';
                data.forEach(([id, name]) => {
                    districtSelect.innerHTML += `<option value="${id}">${name}</option>`;
                });
                districtSelect.dispatchEvent(new Event('change'));
            });
    });

    districtSelect?.addEventListener('change', function () {
        fetch(`/upazilas/${this.value}`)
            .then(res => res.json())
            .then(data => {
                upazilaSelect.innerHTML = '';
                data.forEach(([id, name]) => {
                    upazilaSelect.innerHTML += `<option value="${id}">${name}</option>`;
                });
            });
    });
});
  const input = document.getElementById('profilePictureInput');
  const chosen = document.getElementById('file-chosen');
  if (input && chosen) {
    input.addEventListener('change', function () {
        chosen.textContent = this.files[0] ? this.files[0].name : 'No file chosen';
    });
    }
document.addEventListener('DOMContentLoaded', function () {
  const inputImage = document.getElementById('profilePictureInput');
  const fileChosen = document.getElementById('file-chosen');
  const preview = document.getElementById('profile-preview');

  if (inputImage && fileChosen) {
    inputImage.addEventListener('change', function () {
      if (this.files && this.files[0]) {
        fileChosen.textContent = this.files[0].name;

        if (preview) {
          const reader = new FileReader();
          reader.onload = function (e) {
            preview.src = e.target.result;
          };
          reader.readAsDataURL(this.files[0]);
        }
      }
    });
  }
});
