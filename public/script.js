const themes = ['dark', 'light'];
const hues = ['normal', 'shift', 'polar', 'solar'];
const dropdownIDs = ['space'];

const changeTheme = () =>
{
	let theme = localStorage.getItem('theme') || ((window.getComputedStyle(document.documentElement).getPropertyValue('content') === '"light"') ? themes[1] : themes[0]);
	let themeText = document.getElementById('themeText');
	let hueText = document.getElementById('hueText');

	if(theme === themes[1])
	{
		localStorage.setItem('theme', themes[0]);
		document.body.classList.replace(themes[1], themes[0]);
		themeText.innerHTML = themes[1];

		if(hueText.innerHTML !== hues[0])
		{
			hueText.innerHTML = hues[2];
		}
	} else
	{
		localStorage.setItem('theme', themes[1]);
		document.body.classList.replace(themes[0], themes[1]);
		themeText.innerHTML = themes[0];

		if(hueText.innerHTML !== hues[0])
		{
			hueText.innerHTML = hues[3];
		}
	}
}

const changeHue = () =>
{
	let theme = localStorage.getItem('theme') || ((window.getComputedStyle(document.documentElement).getPropertyValue('content') === '"light"') ? themes[1] : themes[0]);
	let hue = localStorage.getItem('hue');
	let hueText = document.getElementById('hueText');

	if(hue === hues[1])
	{
		localStorage.setItem('hue', hues[0]);
		document.body.classList.replace(hues[1], hues[0]);
		if(theme === themes[0])
		{
			hueText.innerHTML = hues[2];
		} else
		{
			hueText.innerHTML = hues[3];
		}
	} else
	{
		localStorage.setItem('hue', hues[1]);
		document.body.classList.replace(hues[0], hues[1]);
		hueText.innerHTML = hues[0];
	}
}

const init = () =>
{
	// Load or define theme and hue setting
	let storedTheme = localStorage.getItem('theme') || ((window.getComputedStyle(document.documentElement).getPropertyValue('content') === '"light"') ? themes[1] : themes[0]);
	let storedHue = localStorage.getItem('hue') || hues[0];

	document.body.classList.add(storedTheme);
	document.getElementById('themeText').innerHTML = (storedTheme === themes[0]) ? themes[1] : themes[0];

	document.body.classList.add(storedHue);
	document.getElementById('hueText').innerHTML = (storedHue === hues[0]) ? (storedTheme === themes[0]) ? hues[2] : hues[3] : hues[0];

	// Enable animations
	setTimeout(() =>
	{
		document.body.classList.remove('loading');
	}, 0);
}

init();

document.getElementById('themeButton').addEventListener('click', changeTheme);
document.getElementById('hueButton').addEventListener('click', changeHue);

// Loop over dropdowns and add eventlisteners used for extending on click, and retracting when the mouse leaves the navbar
for(let i = 0; i < dropdownIDs.length; i++)
{
	let dropdown = document.getElementById(dropdownIDs[i]).nextElementSibling;
	document.getElementById(dropdownIDs[i]).addEventListener('click', () =>
	{
		// @ts-ignore the style property exists
		dropdown.style.height = (document.getElementById('hiddenList').style.height === '0px') ? `calc(var(--nav-dimensions) * ${dropdown.children.length})` : '0px';
	});
	document.getElementsByTagName('nav')[0].addEventListener('mouseleave', () =>
	{
		// @ts-ignore the style property exists
		dropdown.style.height = '0px';
	});
}
