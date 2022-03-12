using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Input;

namespace ArchitectZad1WPF
{
    internal class AsyncRelayCommand : ICommand
    {
        public event EventHandler CanExecuteChanged;

        bool isExecuting = false;

        Func<Task> action;
        Action<Exception> onExceptionAction;
        public AsyncRelayCommand(Func<Task> action, Action<Exception> onExceptionAction = null)
        {
            this.action = action;
            this.onExceptionAction = onExceptionAction;
        }

        public bool IsExecuting { get => isExecuting; set { isExecuting = value; CanExecuteChanged?.Invoke(this, new EventArgs()); } }

        public bool CanExecute(object parameter)
        {
            return !IsExecuting;
        }

        public async void Execute(object parameter)
        {
            try
            {
                IsExecuting = true;
                if (action != null)
                    await action.Invoke();
            }
            catch (Exception ex)
            {
                onExceptionAction?.Invoke(ex);
            }
            finally
            {
                IsExecuting = false;
            }
        }
    }
}
