// Текст, который оператор отправляет клиенту сразу после заявки.
//
// Смысл один: клиент должен своими глазами сверить реквизиты до того, как
// отправит деньги. Перевод по неверному счёту не отменяется, а ошибку в
// одной цифре человек замечает только тогда, когда видит её отдельной строкой.
//
// Бот не пишет клиентам сам: текст готовится оператору, он его копирует.

function buildClientRecap(order) {
  const {
    id, dir, amount, amountTo, channel, payout,
    recipientName, recipientBank, recipientAccount,
    deliveryAddress, deliveryGeo, hasAttachment,
  } = order;

  const lines = [
    `Заявка №${id}`,
    String(dir.label || ''),
    `Вы отдаёте: ${amount} ${dir.from_cur}`,
    `Вы получаете: ${Number(amountTo).toFixed(2)} ${dir.to_cur}`,
  ];

  if (channel) lines.push(`Отправка: ${channel}`);
  if (payout) lines.push(`Выдача: ${payout}`);

  // Реквизиты идут построчно: так ошибка в цифре видна глазами
  if (recipientName) lines.push(`Получатель: ${recipientName}`);
  if (recipientBank) lines.push(`Банк: ${recipientBank}`);
  if (recipientAccount) lines.push(`Счёт или карта: ${recipientAccount}`);
  if (deliveryAddress) lines.push(`Адрес доставки: ${deliveryAddress}`);
  if (deliveryGeo) lines.push(`Гео: ${deliveryGeo}`);
  if (hasAttachment) lines.push('Приложено фото реквизитов');

  lines.push('');
  lines.push('Проверьте, пожалуйста, ещё раз свои данные: имя, банк и номер счёта.');
  lines.push('Деньги уйдут строго по этим реквизитам, вернуть перевод после отправки нельзя.');
  lines.push('Если что-то указано неверно — напишите здесь, поправим до начала обмена.');

  return lines.join('\n');
}

module.exports = { buildClientRecap };
