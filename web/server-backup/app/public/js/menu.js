document.addEventListener('DOMContentLoaded', () => {
  const menuIcon = document.querySelector('.menu-icon');
  const menuGroup = document.querySelector('.menu-group');
  const menuItems = document.querySelectorAll('.menu-item');

  if (menuIcon && menuGroup) {
    menuIcon.addEventListener('click', (e) => {
      if (window.innerWidth > 720) return;
      e.stopPropagation();
      menuGroup.classList.toggle('active');
    });
  }

  menuItems.forEach((item) => {
    const mainLink = item.querySelector(':scope > a');
    const dropdown = item.querySelector('.dropdown');

    if (!dropdown || !mainLink) return;

    mainLink.addEventListener('click', (e) => {
      if (window.innerWidth <= 720) {
        e.preventDefault();
        e.stopPropagation();

        menuItems.forEach((otherItem) => {
          if (otherItem !== item) {
            otherItem.classList.remove('open');
          }
        });

        item.classList.toggle('open');
      }
    });
  });

  document.addEventListener('click', () => {
    if (window.innerWidth <= 720) {
      if (menuGroup) menuGroup.classList.remove('active');
      menuItems.forEach((item) => item.classList.remove('open'));
    }
  });

  window.addEventListener('resize', () => {
    if (window.innerWidth > 720) {
      if (menuGroup) menuGroup.classList.remove('active');
      menuItems.forEach((item) => item.classList.remove('open'));
    }
  });
});